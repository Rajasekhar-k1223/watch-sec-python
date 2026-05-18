from fastapi import APIRouter, HTTPException # type: ignore
import os
import markdown # type: ignore

router = APIRouter()

DOCS_DIR = "/app/docs/in_app"

@router.get("/{doc_name}")
async def get_documentation(doc_name: str):
    """
    [v2.5.0] In-App Documentation: Serves dynamic Markdown guides to the frontend.
    Allows for real-time updates to forensic and compliance documentation.
    """
    # Sanitize doc_name to prevent path traversal
    safe_name = os.path.basename(doc_name).replace("..", "")
    file_path = os.path.join(DOCS_DIR, f"{safe_name}.md")
    
    if not os.path.exists(file_path):
        # Fallback to general welcome doc
        file_path = os.path.join(DOCS_DIR, "welcome.md")
        if not os.path.exists(file_path):
             return {"content": "<h1>Welcome to Monitorix</h1><p>Documentation coming soon.</p>"}

    with open(file_path, "r") as f:
        md_content = f.read()
        # Convert to HTML for easier frontend rendering
        html_content = markdown.markdown(md_content, extensions=['fenced_code', 'tables'])
        
    return {
        "title": safe_name.replace("_", " ").title(),
        "content": html_content
    }
