"""
Script to check available Gemini models
"""
import google.generativeai as genai
import os
from dotenv import load_dotenv

def main():
    load_dotenv()
    
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[!] GEMINI_API_KEY not found in .env")
        return
    
    genai.configure(api_key=api_key)
    
    print("[*] Checking available Gemini models...\n")
    
    available_models = []
    
    try:
        for model in genai.list_models():
            # Only show models that support content generation
            if 'generateContent' in model.supported_generation_methods:
                print(f"✓ {model.name}")
                print(f"  Display Name: {model.display_name}")
                print(f"  Description: {model.description}")
                print(f"  Input Token Limit: {model.input_token_limit}")
                print(f"  Output Token Limit: {model.output_token_limit}")
                print()
                
                available_models.append(model.name)
    except Exception as e:
        print(f"[!] Error listing models: {e}")
        return
    
    if available_models:
        print(f"\n[+] Found {len(available_models)} models that support generateContent")
        print("\nRecommended for fuzzing:")
        print("  - gemini-2.5-flash (Stable, fast & cheap) ⭐ RECOMMENDED")
        print("  - gemini-2.5-pro (High quality, slower)")
        print("  - gemini-2.0-flash (Alternative, stable)")
        print("  - gemini-3-flash-preview (Experimental, cutting edge)")
    else:
        print("[!] No models found. Check your API key.")

if __name__ == "__main__":
    main()