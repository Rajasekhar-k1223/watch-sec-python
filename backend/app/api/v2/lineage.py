from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import ProcessLineageNode, User
from app.api.deps import get_current_user, verify_agent_signature
from pydantic import BaseModel
import datetime

router = APIRouter()

class ProcessEvent(BaseModel):
    agent_id: str
    process_id: int
    parent_process_id: int = None
    process_name: str
    command_line: str
    image_path: str
    sha256: str = None
    is_malicious: bool = False
    mitre_tactic: str = None
    mitre_technique: str = None

@router.post("/ingest")
async def ingest_process(event: ProcessEvent, db: Session = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    node = ProcessLineageNode(
        AgentId=event.agent_id,
        ProcessId=event.process_id,
        ParentProcessId=event.parent_process_id,
        ProcessName=event.process_name,
        CommandLine=event.command_line,
        ImagePath=event.image_path,
        Sha256=event.sha256,
        IsMalicious=event.is_malicious,
        MitreTactic=event.mitre_tactic,
        MitreTechnique=event.mitre_technique
    )
    db.add(node)
    db.commit()
    return {"status": "success", "node_id": node.Id}

@router.get("/tree/{agent_id}/{root_pid}")
async def get_process_tree(agent_id: str, root_pid: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Recursively fetches the process execution tree.
    In a true Graph DB, this is a single Cypher/AQL query.
    Here we simulate tree building using SQL relationships.
    """
    all_agent_nodes = db.query(ProcessLineageNode).filter(ProcessLineageNode.AgentId == agent_id).all()
    
    # Build adjacency list in memory for fast tree reconstruction
    nodes_by_pid = {}
    children_map = {}
    
    for node in all_agent_nodes:
        node_dict = {
            "id": node.Id,
            "pid": node.ProcessId,
            "ppid": node.ParentProcessId,
            "name": node.ProcessName,
            "cmdline": node.CommandLine,
            "is_malicious": node.IsMalicious,
            "tactic": node.MitreTactic,
            "children": []
        }
        nodes_by_pid[node.ProcessId] = node_dict
        
        ppid = node.ParentProcessId
        if ppid not in children_map:
            children_map[ppid] = []
        children_map[ppid].append(node.ProcessId)

    def build_tree(current_pid):
        if current_pid not in nodes_by_pid:
            return None
        current_node = nodes_by_pid[current_pid]
        
        # Recursively attach children
        if current_pid in children_map:
            for child_pid in children_map[current_pid]:
                child_tree = build_tree(child_pid)
                if child_tree:
                    current_node["children"].append(child_tree)
                    
        return current_node

    tree = build_tree(root_pid)
    if not tree:
        raise HTTPException(status_code=404, detail="Root process not found")
        
    return {"status": "success", "agent_id": agent_id, "tree": tree}
