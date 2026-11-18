from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader

WEB_DIR = Path(__file__).parent
HOST = "127.0.0.1"
PORT = 8000

templates = Jinja2Templates(
    env=Environment(loader=FileSystemLoader(WEB_DIR / "templates"), autoescape=True)
)

app = FastAPI(title="reconmap")
app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html", {"scans": []})


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def main() -> None:
    uvicorn.run(app, host=HOST, port=PORT)
