from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.auth.router import router as auth_router

app = FastAPI()

origins = [
    "http://127.0.0.1:3000",
    "https://speaking-commons-treasures-lets.trycloudflare.com",
    "http://localhost:3000",
    "http://localhost:8000", # Обязательно добавьте сам бэкенд, чтобы Swagger не ругался
]

# 1. МИДДЛВАР ДЛЯ OAUTH СЕССИЙ
app.add_middleware(
    SessionMiddleware, 
    secret_key="your-super-secret-key",
    session_cookie="oauth_session", # Отдельное имя для OAuth!
    same_site="none",               
    https_only=True,                # Обязательно True для туннеля
)

# 2. CORS МИДДЛВАР (срабатывает первым на входе запроса)
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,            
    allow_credentials=True,         # Позволяет передавать И oauth_session, И access_token
    allow_methods=["*"],              
    allow_headers=["*"],              
)

app.include_router(auth_router)
