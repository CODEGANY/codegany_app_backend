import os
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

# Load environment variables
supabase_url: str = os.environ.get("SUPABASE_PROJECT_URL")
supabase_key: str = os.environ.get("SUPABASE_API_KEY")

# Initialize Supabase client
supabase_client = create_client(supabase_url, supabase_key)