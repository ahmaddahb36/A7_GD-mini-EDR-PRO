
from db.models import get_pending_command, update_command

def get_command(ip):
    cmd = get_pending_command(ip)
    return cmd

def complete_command(cmd_id, output, status="done"):
    update_command(cmd_id, output, status=status)
