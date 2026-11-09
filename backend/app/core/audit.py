from app.models import AuditEvent


def record(db, actor, area, action, object, outcome, detail, policy_version=None):
    db.add(AuditEvent(actor=actor, area=area, action=action, object=object,
                      outcome=outcome, detail=detail, policy_version=policy_version))
    db.flush()
