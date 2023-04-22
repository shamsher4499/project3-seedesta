USER_TYPE = (
    ('USER', 'USER'),
    ('VENDOR', 'VENDOR')
)

NOTIFICATION_TYPE = (
    ('GOAL', 'GOAL'),
    ('POST', 'POST'),
    ('LIKE', 'LIKE'),
    ('INVITATION', 'INVITATION'),
    ('FOLLOW', 'FOLLOW'),
    ('REQUEST', 'REQUEST')
)

USER_CATEGORY = (
    ('NEW', 'NEW'),
    ('VERIFIED', 'VERIFIED'),
    ('PRO', 'PRO')
)

GOAL_TYPE = (
    ('INDIVIDUAL', 'INDIVIDUAL'),
    ('GROUP', 'GROUP')
)

PAYMENT_METHOD = (
    ('AUTO', 'AUTO'),
    ('MANUAL', 'MANUAL')
)

GOAL_AS = (
    ('PRODUCT', 'PRODUCT'),
    ('CUSTOM', 'CUSTOM')
)

GOAL_PRIORITY = (
    ('PUBLIC', 'PUBLIC'),
    ('PRIVATE', 'PRIVATE')
)

GOAL_STATUS = (
    ('ACTIVE ', 'ACTIVE'),
    ('COMPLETED', 'COMPLETED')
)

GOAL_DURATION = (
    ('MONTHLY ', 'MONTHLY'),
    ('QUARTERLY', 'QUARTERLY'),
    ('YEARLY', 'YEARLY'),
    ('CUSTOM-DATE', 'CUSTOM-DATE')
)

QUERY_STATUS = (
    ('PENDING ', 'PENDING'),
    ('RESOLVED', 'RESOLVED'),
    # ('VIEW', 'VIEW'),
)

ORDER_STATUS = (
    ('PENDING ', 'PENDING'),
    ('COMPLETED', 'COMPLETED'),
)


CATEGORY = (
    ('SERVICE', 'SERVICE'),
    ('PRODUCT', 'PRODUCT'),
)

RETURN_PERIOD = (
    ('7 DAYS', '7 DAYS'),
    ('15 DAYS', '15 DAYS'),
    ('30 DAYS', '30 DAYS'),
    ('45 DAYS', '45 DAYS'),
)

CHOCIES_PLAN_STATUS = (
    ('ACTIVE', 'ACTIVE'),
    ('CANCELLED', 'CANCELLED'),
)

GOAL_PAYMENT_STATUS = (
    ('PENDING', 'PENDING'),
    ('COMPLETED', 'COMPLETED'),
)