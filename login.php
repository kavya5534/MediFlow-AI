<?php
declare(strict_types=1);
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';
if (!empty($_SESSION['user_id'])) { header('Location: index.php'); exit; }
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim((string)($_POST['email'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $password === '') {
        $error = 'Enter a valid email and password.';
    } else {
        $stmt = $pdo->prepare('SELECT id, full_name, email, password_hash, role FROM users WHERE email = ? LIMIT 1');
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user && password_verify($password, $user['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = (int)$user['id'];
            $_SESSION['user_name'] = $user['full_name'];
            $_SESSION['user_role'] = $user['role'];
            header('Location: index.php'); exit;
        }
        $error = 'Incorrect email or password.';
    }
}
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in | MediFlow AI</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:linear-gradient(135deg,#eaf2ff,#f7fbff);font-family:Segoe UI,Arial,sans-serif;color:#182338}.card{width:min(420px,92vw);background:#fff;border:1px solid #e4eaf3;border-radius:22px;padding:34px;box-shadow:0 18px 55px #18345a16}.brand{font-size:27px;font-weight:800;color:#123052}.brand span{color:#1b9aaa}.sub{color:#718096;margin:8px 0 26px}label{display:block;font-weight:600;margin:16px 0 7px}input{width:100%;padding:13px 14px;border:1px solid #d7e0ec;border-radius:10px;font-size:15px}button{width:100%;border:0;background:#176b87;color:white;padding:14px;border-radius:10px;font-size:16px;font-weight:700;margin-top:22px;cursor:pointer}.error{background:#fff0f0;color:#a32929;padding:11px;border-radius:9px}.note{font-size:12px;color:#718096;margin-top:18px;line-height:1.5}
</style></head><body><main class="card"><div class="brand">MediFlow<span> AI</span></div><p class="sub">Hospital operations · Sign in to continue</p><?php if($error): ?><div class="error"><?= h($error) ?></div><?php endif; ?><form method="post" autocomplete="on"><label for="email">Email address</label><input id="email" name="email" type="email" required autocomplete="username" placeholder="admin@mediflow.local"><label for="password">Password</label><input id="password" name="password" type="password" required autocomplete="current-password" placeholder="Enter your password"><button type="submit">Sign in</button></form><p class="note">For first-time setup, run setup_admin.php once, create your admin account, then delete setup_admin.php.</p></main></body></html>
