<?php
require_once 'db_config_pdo.php';

$keyword = $_GET['keyword'] ?? '';

if (!mb_check_encoding($keyword, 'UTF-8')) {
    http_response_code(400);
    exit("Invalid encoding.");
}

if (mb_strlen($keyword, 'UTF-8') > 100) {
    http_response_code(400);
    exit("Keyword too long.");
}

function e($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$stmt = $pdo->prepare(
    "SELECT id, name, illness_history
     FROM patient_records
     WHERE name LIKE :keyword
     LIMIT 20"
);

$stmt->execute([
    "keyword" => "%" . $keyword . "%"
]);

$rows = $stmt->fetchAll();

if ($rows) {
    foreach ($rows as $row) {
        echo "<div>";
        echo "Result found for keyword: " . e($keyword) . "<br>";
        echo "Patient: " . e($row['name']) . " | History: " . e($row['illness_history']);
        echo "</div><hr>";
    }
} else {
    echo "No records found for: " . e($keyword);
}
?>