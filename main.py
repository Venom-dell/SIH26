import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router

app = FastAPI(title="Email Forensic Analysis API")

# Configure permissive CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the router
app.include_router(router)

if __name__ == "__main__":
    # Setup Uvicorn run configuration
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
