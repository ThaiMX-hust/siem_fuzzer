import google.generativeai as genai
import os
import json
from pathlib import Path
from typing import Optional
import hashlib
import time

class LLMMutator:
    def __init__(self, model="gemini-2.5-flash", use_cache=True):
        """
        Initialize LLM Mutator with Google Gemini
        
        Args:
            model: Gemini model to use (gemini-2.5-flash, gemini-2.5-pro, gemini-2.0-flash, etc.)
            use_cache: Whether to cache LLM responses to reduce API calls
        """
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY not found in environment. "
                "Set it in .env file or environment variables.\n"
                "Get your API key from: https://makersuite.google.com/app/apikey"
            )
        
        # Configure Gemini
        genai.configure(api_key=api_key)
        
        # FIX: Normalize model name
        # Remove 'models/' prefix if present, then add it back
        model = model.replace("models/", "")
        
        # Map common model names to official API names (with models/ prefix)
        model_mapping = {
            # Gemini 2.5 (Latest stable - June 2025)
            "gemini-2.5-flash": "models/gemini-2.5-flash",
            "gemini-2.5-pro": "models/gemini-2.5-pro",
            "gemini-flash": "models/gemini-2.5-flash",  # Alias to latest
            "gemini-pro": "models/gemini-2.5-pro",
            
            # Gemini 2.0
            "gemini-2.0-flash": "models/gemini-2.0-flash",
            "gemini-2.0-flash-exp": "models/gemini-2.0-flash-exp",
            
            # Gemini 3.0 (Preview)
            "gemini-3-flash": "models/gemini-3-flash-preview",
            "gemini-3-pro": "models/gemini-3-pro-preview",
            
            # Legacy (deprecated, will fail)
            "gemini-1.5-flash": "models/gemini-2.5-flash",  # Fallback
            "gemini-1.5-pro": "models/gemini-2.5-pro",  # Alias
        }
        
        # Use mapped name (with models/ prefix) or add prefix if missing
        full_model_name = model_mapping.get(model, model)
        
        # Ensure models/ prefix exists
        if not full_model_name.startswith("models/"):
            full_model_name = f"models/{full_model_name}"
        
        self.model_name = full_model_name
        
        # Try to initialize model
        try:
            self.model = genai.GenerativeModel(full_model_name)
            print(f"[+] Successfully connected to {full_model_name}")
        except Exception as e:
            print(f"[!] Failed to initialize model '{model}': {e}")
            print("[*] Available models:")
            
            # List available models
            try:
                for m in genai.list_models():
                    if 'generateContent' in m.supported_generation_methods:
                        print(f"    - {m.name}")
            except Exception as list_error:
                print(f"    Could not list models: {list_error}")
            
            raise
        
        # Configure generation parameters
        self.generation_config = {
            "temperature": 0.7,
            "top_p": 0.95,
            "top_k": 40,
            "max_output_tokens": 200,
        }
        
        # Safety settings (disable blocking for technical content)
        self.safety_settings = [
            {
                "category": "HARM_CATEGORY_HARASSMENT",
                "threshold": "BLOCK_NONE"
            },
            {
                "category": "HARM_CATEGORY_HATE_SPEECH",
                "threshold": "BLOCK_NONE"
            },
            {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "threshold": "BLOCK_NONE"
            },
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                "threshold": "BLOCK_NONE"
            },
        ]
        
        self.use_cache = use_cache
        
        # Cache setup
        if use_cache:
            self.cache_dir = Path(__file__).parent.parent.parent / "data" / "llm_cache"
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self.cache_file = self.cache_dir / f"mutations_{model}.json"
            self.cache = self._load_cache()
        else:
            self.cache = {}
        
        # Stats
        self.stats = {
            "total_calls": 0,
            "cache_hits": 0,
            "api_calls": 0,
            "failures": 0
        }
        
        print(f"[+] LLM Mutator initialized with {model}")
    
    def _load_cache(self) -> dict:
        """Load mutation cache from disk"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[WARNING] Failed to load cache: {e}")
        return {}
    
    def _save_cache(self):
        """Save mutation cache to disk"""
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            print(f"[WARNING] Failed to save cache: {e}")
    
    def _get_cache_key(self, payload: str, target_rule: str, history: list) -> str:
        """Generate cache key from inputs"""
        content = f"{payload}|{target_rule}|{history}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def mutate_payload(
        self, 
        payload: str, 
        target_rule: str, 
        mutation_history: list,
        fallback_on_error: bool = True
    ) -> Optional[str]:
        """
        Generate obfuscated payload variant using Gemini
        
        Args:
            payload: Original command to obfuscate
            target_rule: SIEM rule name being targeted
            mutation_history: List of previous mutations for diversity
            fallback_on_error: Return original payload if LLM fails
        
        Returns:
            Obfuscated payload or None if failed (and fallback disabled)
        """
        self.stats["total_calls"] += 1
        
        # Check cache
        cache_key = self._get_cache_key(payload, target_rule, mutation_history[-3:])
        if self.use_cache and cache_key in self.cache:
            self.stats["cache_hits"] += 1
            return self.cache[cache_key]
        
        # Build prompt
        prompt = self._build_prompt(payload, target_rule, mutation_history)
        
        # Call Gemini
        try:
            self.stats["api_calls"] += 1
            
            # Generate content
            response = self.model.generate_content(
                prompt,
                generation_config=self.generation_config,
                safety_settings=self.safety_settings
            )
            
            # Check if response was blocked
            if not response.text:
                raise ValueError("Response was blocked by safety filters")
            
            mutated = response.text.strip()
            
            # Validate output
            if not mutated or len(mutated) < 5:
                raise ValueError("LLM returned empty or too short response")
            
            # Remove markdown code blocks if present
            mutated = self._clean_response(mutated)
            
            # Cache result
            if self.use_cache:
                self.cache[cache_key] = mutated
                if len(self.cache) % 10 == 0:  # Save every 10 new entries
                    self._save_cache()
            
            return mutated
        
        except Exception as e:
            self.stats["failures"] += 1
            print(f"[!] LLM mutation failed: {e}")
            
            if fallback_on_error:
                return payload  # Return original as fallback
            else:
                return None
    
    def _build_prompt(self, payload: str, target_rule: str, mutation_history: list) -> str:
        """Build prompt with explicit evasion techniques"""
        recent_history = mutation_history[-3:] if mutation_history else []
        history_str = "\n".join(f"  {i+1}. {m}" for i, m in enumerate(recent_history))
        
        prompt = f"""You are a Windows command obfuscation expert specializing in SIEM evasion.

Target SIEM Rule: {target_rule}

Original Payload:
{payload}

Previous Mutations (avoid repetition):
{history_str if recent_history else "  None"}

Apply ONE of these 5 evasion techniques:

1. **INSERTION**: Insert characters between keywords
   Example: schtasks /create → schtasks /"create"
   
2. **SUBSTITUTION**: Replace with equivalent representations
   Example: curl -O http://... → curl --remote-name http://...
   
3. **OMISSION**: Remove non-essential parts
   Example: cscript.exe → cscript
   
4. **REORDERING**: Change argument order
   Example: procdump -ma lsass → procdump lsass -ma
   
5. **RECODING**: Encode values differently
   Example: address=127.0.0.1 → address=2130706433

Requirements:
- **Maintain EXACT functionality** (must execute correctly)
- Be **syntactically valid** on Windows
- Be **different** from previous mutations
- Use Windows-native obfuscation (caret ^, quotes, case mixing, etc.)

Return ONLY the obfuscated command on ONE line, no explanation.
"""
        return prompt
    
    def _clean_response(self, response: str) -> str:
        """Remove markdown code blocks and extra whitespace"""
        # Remove markdown code blocks
        if response.startswith("```") and response.endswith("```"):
            lines = response.split("\n")
            # Remove first and last line (``` markers)
            response = "\n".join(lines[1:-1])
        
        # Remove inline code markers
        response = response.replace("`", "")
        
        # Normalize whitespace
        response = response.strip()
        
        return response
    
    def get_stats(self) -> dict:
        """Get mutation statistics"""
        stats = self.stats.copy()
        if stats["total_calls"] > 0:
            stats["cache_hit_rate"] = stats["cache_hits"] / stats["total_calls"]
            stats["failure_rate"] = stats["failures"] / stats["total_calls"]
        else:
            stats["cache_hit_rate"] = 0.0
            stats["failure_rate"] = 0.0
        return stats
    
    def print_stats(self):
        """Print mutation statistics"""
        stats = self.get_stats()
        print("\n[*] LLM Mutation Statistics:")
        print(f"    Total calls: {stats['total_calls']}")
        print(f"    Cache hits: {stats['cache_hits']} ({stats['cache_hit_rate']*100:.1f}%)")
        print(f"    API calls: {stats['api_calls']}")
        print(f"    Failures: {stats['failures']} ({stats['failure_rate']*100:.1f}%)")


# Standalone test
if __name__ == "__main__":
    import sys
    
    # Load .env
    from dotenv import load_dotenv
    load_dotenv()
    
    try:
        mutator = LLMMutator(model="gemini-2.5-flash")
        
        # Test mutation
        payload = "net.exe start Spooler"
        print(f"\n[*] Testing mutation on: {payload}")
        
        result = mutator.mutate_payload(
            payload=payload,
            target_rule="win_net_start_service",
            mutation_history=[]
        )
        
        print(f"[+] Result: {result}")
        
        # Test with history
        print("\n[*] Testing with mutation history...")
        result2 = mutator.mutate_payload(
            payload=payload,
            target_rule="win_net_start_service",
            mutation_history=[result]
        )
        
        print(f"[+] Result 2: {result2}")
        
        # Print stats
        mutator.print_stats()
        
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)