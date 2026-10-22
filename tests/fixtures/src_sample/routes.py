"""Piccolo sorgente d'esempio con un paio di route (solo per i test)."""

from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/api/login")
def login():
    return {"token": "x"}
