role Admin
role Owner
role Hr
resource Inventory
resource Onboarding
resource Soundbox
resource Cases
action hide 
action update
action delete
action view 
action search

inrole role(Admin, Hr)
inrole role(Admin, Owner)
priv permission(Owner, Inventory, hide)
priv permission(Owner, Soundbox, hide)
priv permission(Owner, Onboarding, hide)
priv permission(Owner, Onboarding, view)

priv permission(Admin, Onboarding, view)
priv permission(Admin, Onboarding, update)
priv permission(Admin, Cases, update)
priv permission(Admin, Cases, view)

priv permission(Hr, Inventory, delete)
priv permission(Hr, Onboarding, search)
priv permission(Hr, Onboarding, view)

