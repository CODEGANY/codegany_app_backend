import os
from dotenv import load_dotenv

from fastapi import FastAPI
from supabase import create_client, Client

load_dotenv()

app: FastAPI = FastAPI()
url: str = os.environ.get("SUPABASE_PROJECT_URL")
key: str = os.environ.get("SUPABASE_API_KEY")
supabase: Client = create_client(url, key)


@app.get("/")
def root():
    return {"Hello": "World"}
