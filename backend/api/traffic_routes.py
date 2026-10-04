import sqlite3
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
try:
    from backend.security.traffic_controller import TrafficController
    from backend.app.auth import get_current_user
except ImportError:
    try:
        from security.traffic_controller import TrafficController
        from app.auth import get_current_user
    except ImportError:
        from ..security.traffic_controller import TrafficController
        from ..app.auth import get_current_user

router = APIRouter(prefix="/api/traffic", tags=["Traffic Control"])
controller = TrafficController()

class RuleRequest(BaseModel):
    rule_name: str
    direction: str  # in | out | both
    action: str     # allow | block
    protocol: str = 'any'
    local_port: str = 'any'
    remote_ip: str = 'any'
    admin_locked: bool = True
    notes: str = ''

class RemoveRuleRequest(BaseModel):
    rule_name: str

@router.get("/rules")
async def get_rules(current_user = Depends(get_current_user)):
    rules = controller.get_all_rules()
    user_role = getattr(current_user, 'role', 'user')
    if user_role != 'admin':
        # Users see rules but cannot see admin-locked status details
        for rule in rules:
            rule['can_modify'] = not bool(rule['is_admin_locked'])
    else:
        for rule in rules:
            rule['can_modify'] = True
    return {'rules': rules, 'total': len(rules)}

@router.post("/rules/add")
async def add_rule(req: RuleRequest, current_user = Depends(get_current_user)):
    user_role = getattr(current_user, 'role', 'user')
    user_email = getattr(current_user, 'email', '') or getattr(current_user, 'username', 'admin')
    if user_role != 'admin':
        raise HTTPException(403, "Only administrators can add firewall rules")
    result = controller.add_rule(
        req.rule_name, req.direction, req.action,
        req.protocol, req.local_port, req.remote_ip,
        user_email, req.admin_locked, req.notes
    )
    if not result.get('success'):
        if result.get('error') == 'admin_required':
            raise HTTPException(403, detail={"error": "admin_required", "message": result.get("message", "Managing Windows firewall rules requires Administrator privileges.")})
        raise HTTPException(400, result.get('error', 'Failed to add rule'))
    return result

@router.delete("/rules/{rule_name}")
async def remove_rule(rule_name: str, current_user = Depends(get_current_user)):
    user_role = getattr(current_user, 'role', 'user')
    user_email = getattr(current_user, 'email', '') or getattr(current_user, 'username', 'user')
    is_admin = user_role == 'admin'
    if not controller.check_user_can_modify(rule_name, is_admin):
        raise HTTPException(403, "This rule is admin-locked and cannot be modified by users")
    result = controller.remove_rule(rule_name, user_email, is_admin)
    if not result.get('success'):
        if result.get('error') == 'admin_required':
            raise HTTPException(403, detail={"error": "admin_required", "message": result.get("message", "Managing Windows firewall rules requires Administrator privileges.")})
        raise HTTPException(400, result.get('error', 'Failed to remove rule'))
    return result

@router.post("/rules/toggle-lock/{rule_name}")
async def toggle_lock(rule_name: str, current_user = Depends(get_current_user)):
    user_role = getattr(current_user, 'role', 'user')
    if user_role != 'admin':
        raise HTTPException(403, "Only administrators can lock/unlock rules")
    with sqlite3.connect(controller.db_path) as conn:
        conn.execute(
            "UPDATE firewall_rules SET is_admin_locked = NOT is_admin_locked WHERE rule_name = ?",
            (rule_name,)
        )
        conn.commit()
    return {'success': True}