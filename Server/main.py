from fastapi import FastAPI

from .router import router

app = FastAPI(title="6200 Group Chat API")
app.include_router(router)