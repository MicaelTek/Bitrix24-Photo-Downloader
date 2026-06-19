<?php
/**
 * Bitrix24 Fotos - Endpoint de Auditoria e Painel (cPanel)
 * 
 * Instale este arquivo em uma pasta publica do seu cPanel.
 * Ele cria e mantem o banco SQLite "auditoria.sqlite" automaticamente
 * na mesma pasta onde for executado.
 */

// ============================================================================
// CONFIGURACAO DE SEGURANCA
// ============================================================================
// Troque esse token se quiser, mas certifique-se de usar o mesmo no app Python
define('SECRET_TOKEN', 'BX24_LOG_77A8F932D939');

// Senha para acessar o painel de visualização web
define('VIEWER_PASSWORD', 'admin');

define('MAX_PAYLOAD_SIZE', 10240); // 10KB maximo
// ============================================================================

// O banco de dados ficara no mesmo diretorio que este script
$db_file = __DIR__ . '/auditoria.sqlite';

try {
    // Conecta/Cria o banco de dados
    $db = new PDO('sqlite:' . $db_file);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Cria a tabela se nao existir
    $query = "CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        data_hora DATETIME DEFAULT CURRENT_TIMESTAMP,
        nome TEXT,
        departamento TEXT,
        maquina TEXT,
        ip TEXT,
        acao TEXT,
        detalhes TEXT
    )";
    $db->exec($query);

} catch (PDOException $e) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        http_response_code(500);
        header("Content-Type: application/json");
        echo json_encode(["status" => "error", "message" => "Erro interno no servidor de banco de dados."]);
    } else {
        die("Erro ao conectar no banco SQLite: " . $e->getMessage());
    }
    exit;
}

// ============================================================================
// MODO PAINEL WEB (GET)
// ============================================================================
if ($_SERVER['REQUEST_METHOD'] !== 'POST' && $_SERVER['REQUEST_METHOD'] !== 'OPTIONS') {
    session_start();
    
    // Verifica login
    if (isset($_POST['senha'])) {
        if ($_POST['senha'] === VIEWER_PASSWORD) {
            $_SESSION['log_auth'] = true;
        } else {
            $erro = "Senha incorreta.";
        }
    }
    
    // Logout
    if (isset($_GET['logout'])) {
        session_destroy();
        header("Location: ?");
        exit;
    }

    // Output HTML
    header("Content-Type: text/html; charset=UTF-8");
    ?>
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Auditoria - Bitrix24 Downloader</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f6f9; color: #333; margin: 0; padding: 20px; }
            .container { max-width: 1200px; margin: 0 auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            h1 { color: #1e293b; margin-top: 0; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
            th { background: #f8fafc; font-weight: 600; color: #475569; }
            tr:hover { background: #f1f5f9; }
            .login-box { max-width: 300px; margin: 100px auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }
            input[type=password] { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #cbd5e1; border-radius: 4px; box-sizing: border-box; }
            button { background: #2563eb; color: #fff; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; width: 100%; font-weight: bold; transition: 0.2s; }
            button:hover { background: #1d4ed8; }
            .error { color: #ef4444; margin-bottom: 10px; font-weight: bold; }
            .btn-logout { background: #ef4444; float: right; width: auto; margin-top: -5px; }
            .btn-logout:hover { background: #dc2626; }
            .badge { background: #e2e8f0; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
            .badge-login { background: #dcfce7; color: #166534; }
            .badge-download { background: #dbeafe; color: #1e40af; }
            .badge-erro { background: #fee2e2; color: #991b1b; }
        </style>
    </head>
    <body>
    <?php if (!isset($_SESSION['log_auth'])): ?>
        <div class="login-box">
            <h2>Acesso Restrito</h2>
            <?php if(isset($erro)) echo "<div class='error'>$erro</div>"; ?>
            <form method="POST">
                <input type="password" name="senha" placeholder="Senha de acesso" required>
                <button type="submit">Entrar</button>
            </form>
        </div>
    <?php else: ?>
        <div class="container">
            <a href="?logout=1"><button class="btn-logout">Sair</button></a>
            <h1>Logs de Auditoria do App</h1>
            <table>
                <thead>
                    <tr>
                        <th>Data/Hora (Servidor)</th>
                        <th>Ação</th>
                        <th>Usuário</th>
                        <th>Departamento</th>
                        <th>Máquina / IP</th>
                        <th>Detalhes</th>
                    </tr>
                </thead>
                <tbody>
                <?php
                    $stmt = $db->query("SELECT * FROM logs ORDER BY id DESC LIMIT 500");
                    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                        $acao = htmlspecialchars($row['acao']);
                        $badge_class = '';
                        if (strpos($acao, 'LOGIN') !== false) $badge_class = 'badge-login';
                        if (strpos($acao, 'DOWNLOAD') !== false) $badge_class = 'badge-download';
                        if (strpos($acao, 'ERRO') !== false || strpos($acao, 'FALHA') !== false) $badge_class = 'badge-erro';

                        echo "<tr>";
                        echo "<td>" . date('d/m/Y H:i:s', strtotime($row['data_hora'])) . "</td>";
                        echo "<td><span class='badge $badge_class'>" . $acao . "</span></td>";
                        echo "<td><strong>" . htmlspecialchars($row['nome']) . "</strong></td>";
                        echo "<td>" . htmlspecialchars($row['departamento']) . "</td>";
                        echo "<td><small><strong>" . htmlspecialchars($row['maquina']) . "</strong><br>" . htmlspecialchars($row['ip']) . "</small></td>";
                        echo "<td>" . nl2br(htmlspecialchars($row['detalhes'])) . "</td>";
                        echo "</tr>";
                    }
                ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
    </body>
    </html>
    <?php
    exit;
}

// ============================================================================
// MODO API (POST) - RECEBIMENTO DE LOGS
// ============================================================================

// Permite chamadas de qualquer lugar (CORS) para o aplicativo desktop enviar os dados
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, X-Audit-Token");

// Pre-flight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

header("Content-Type: application/json");

// 1. Verificacao de Tamanho do Payload
if (isset($_SERVER['CONTENT_LENGTH']) && $_SERVER['CONTENT_LENGTH'] > MAX_PAYLOAD_SIZE) {
    http_response_code(413);
    echo json_encode(["status" => "error", "message" => "Payload muito grande."]);
    exit;
}

// 2. Verificacao de Autenticacao
$headers = getallheaders();
$client_token = isset($headers['X-Audit-Token']) ? $headers['X-Audit-Token'] : (isset($headers['x-audit-token']) ? $headers['x-audit-token'] : '');

if ($client_token !== SECRET_TOKEN) {
    http_response_code(401);
    echo json_encode(["status" => "error", "message" => "Acesso nao autorizado. Token invalido."]);
    exit;
}

// Le o corpo da requisicao JSON enviada pelo Python
$json = file_get_contents('php://input');
$data = json_decode($json, true);

if (!$data) {
    http_response_code(400);
    echo json_encode(["status" => "error", "message" => "JSON invalido ou ausente."]);
    exit;
}

// Coleta e higieniza as informacoes
$nome = isset($data['nome']) ? htmlspecialchars(strip_tags(trim($data['nome']))) : 'Nao informado';
$departamento = isset($data['departamento']) ? htmlspecialchars(strip_tags(trim($data['departamento']))) : 'Nao informado';
$maquina = isset($data['maquina']) ? htmlspecialchars(strip_tags(trim($data['maquina']))) : 'Desconhecida';
$acao = isset($data['acao']) ? htmlspecialchars(strip_tags(trim($data['acao']))) : 'INDEFINIDO';
$detalhes = isset($data['detalhes']) ? htmlspecialchars(strip_tags(trim($data['detalhes']))) : '';
$ip = $_SERVER['REMOTE_ADDR'];

try {
    // Insere no banco
    $stmt = $db->prepare("INSERT INTO logs (nome, departamento, maquina, ip, acao, detalhes) VALUES (:nome, :departamento, :maquina, :ip, :acao, :detalhes)");
    $stmt->bindValue(':nome', $nome);
    $stmt->bindValue(':departamento', $departamento);
    $stmt->bindValue(':maquina', $maquina);
    $stmt->bindValue(':ip', $ip);
    $stmt->bindValue(':acao', $acao);
    $stmt->bindValue(':detalhes', $detalhes);
    $stmt->execute();

    http_response_code(201);
    echo json_encode(["status" => "success", "message" => "Log registrado."]);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Erro no banco de dados."]);
}
?>
