@{
    # ============================================================
    #  Role catalog — the heart of the RBAC / JML model.
    #  A "role" (job title) maps to a department, a target OU leaf,
    #  and the exact set of security groups a person in that role gets.
    #  Joiner assigns these; Mover swaps them; Leaver strips them all.
    #  Add a new role here and every script picks it up automatically.
    # ============================================================

    'IT Support' = @{
        Department = 'IT'
        OU         = 'IT'          # leaf under OU=Users
        Groups     = @('Role-IT', 'RES-Helpdesk-RW', 'RES-Fileshare-RW')
    }
    'HR Specialist' = @{
        Department = 'HR'
        OU         = 'HR'
        Groups     = @('Role-HR', 'RES-HR-Share-RW', 'RES-Fileshare-RO')
    }
    'Financial Analyst' = @{
        Department = 'Finance'
        OU         = 'Finance'
        Groups     = @('Role-Finance', 'RES-Finance-Share-RW', 'RES-Fileshare-RO')
    }
    'Sales Representative' = @{
        Department = 'Sales'
        OU         = 'Sales'
        Groups     = @('Role-Sales', 'RES-CRM-RW', 'RES-Fileshare-RO')
    }
}
