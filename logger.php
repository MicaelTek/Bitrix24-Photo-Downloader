<?php
/**
 * Bitrix24 Fotos - Endpoint de Auditoria (cPanel)
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
define('MAX_PAYLOAD_SIZE', 10240); // 10KB maximo
// ============================================================================

// Permite chamadas de qualquer lugar (CORS) para o aplicativo desktop enviar os dados
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type, X-Audit-Token");
header("Content-Type: application/json");

// Se for requisicao OPTIONS (pre-flight), apenas retorna 200 OK
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

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

    // Se nao for POST, mostra uma mensagem simples
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(["status" => "info", "message" => "Endpoint de auditoria ativo."]);
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

    // Coleta e higieniza as informacoes contra XSS (strip_tags e htmlspecialchars)
    $nome = isset($data['nome']) ? htmlspecialchars(strip_tags(trim($data['nome']))) : 'Nao informado';
    $departamento = isset($data['departamento']) ? htmlspecialchars(strip_tags(trim($data['departamento']))) : 'Nao informado';
    $maquina = isset($data['maquina']) ? htmlspecialchars(strip_tags(trim($data['maquina']))) : 'Desconhecida';
    $acao = isset($data['acao']) ? htmlspecialchars(strip_tags(trim($data['acao']))) : 'INDEFINIDO';
    $detalhes = isset($data['detalhes']) ? htmlspecialchars(strip_tags(trim($data['detalhes']))) : '';
    $ip = $_SERVER['REMOTE_ADDR'];

    // Insere no banco
    $stmt = $db->prepare("INSERT INTO logs (nome, departamento, maquina, ip, acao, detalhes) VALUES (:nome, :departamento, :maquina, :ip, :acao, :detalhes)");
    $stmt->bindValue(':nome', $nome);
    $stmt->bindValue(':departamento', $departamento);
    $stmt->bindValue(':maquina', $maquina);
    $stmt->bindValue(':ip', $ip);
    $stmt->bindValue(':acao', $acao);
    $stmt->bindValue(':detalhes', $detalhes);
    $stmt->execute();

    // Retorna sucesso
    http_response_code(201);
    echo json_encode(["status" => "success", "message" => "Log registrado."]);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Erro no banco de dados."]);
}
?>
