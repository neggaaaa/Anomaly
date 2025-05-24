from fastapi import FastAPI, UploadFile, HTTPException
from services.analyzer import analyze_logs
from services.reporter import generate_report
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/upload")
async def upload_file(file: UploadFile):
    if not file:
        raise HTTPException(status_code=400, detail="File not provided")
    file_extension = f".{file.filename.split('.')[-1].lower()}"
    if file_extension not in ['.csv', '.log', '.txt', '.evtx']:
        raise HTTPException(status_code=400, detail="Only .csv, .log, .txt or .evtx files are supported")

    content_bytes = await file.read()

    if file_extension in ['.csv', '.log', '.txt']:
        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise HTTPException(status_code=400, detail=f"File decoding error: {str(e)}")
    else:
        content = content_bytes

    analysis = await analyze_logs(content, file_extension)
    report = await generate_report(analysis)
    return report

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
@app.get("/")
def root():
    return {"message": "API работает!"}