from fastapi import FastAPI

app = FastAPI(
    title="Enterprise Network Defense API",
    version="1.0.0"
)

@app.get("/")
def home():
    return {"message": "Backend Running Successfully"}