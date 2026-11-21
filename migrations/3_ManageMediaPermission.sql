INSERT INTO global_permissions (permission) VALUES ('manage_media')
ON CONFLICT (permission) DO NOTHING;

INSERT INTO global_user_permissions (user_email, permission)
SELECT user_email, 'manage_media'
FROM global_user_permissions
WHERE permission IN ('manage_list', 'manage_recipient', 'change_permission')
GROUP BY user_email
HAVING COUNT(DISTINCT permission) = 3
ON CONFLICT (user_email, permission) DO NOTHING;
