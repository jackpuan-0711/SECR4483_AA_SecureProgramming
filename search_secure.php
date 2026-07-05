<?php
// search_secure.php - Secure Patient Search using PDO and output encoding

require_once 'db_config_pdo.php';

$keyword = $_GET['keyword'] ?? '';

if (!mb_check_encoding($keyword, 'UTF-8')) {
    http_response_code(400);
    exit("Invalid UTF-8 input.");
}

$keyword = trim($keyword);

if ($keyword === '') {
    http_response_code(400);
    exit("Keyword is required.");
}

if (mb_strlen($keyword, 'UTF-8') > 100) {
    http_response_code(400);
    exit("Keyword is too long.");
}

$safeKeyword = htmlspecialchars($keyword, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$stmt = $pdo->prepare(
    "SELECT id, name, illness_history 
     FROM patient_records 
     WHERE name LIKE :keyword 
     LIMIT 20"
);

$stmt->execute([
    'keyword' => '%' . $keyword . '%'
]);

$records = $stmt->fetchAll();

if ($records) {
    foreach ($records as $row) {
        $safeName = htmlspecialchars($row['name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $safeHistory = htmlspecialchars($row['illness_history'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        echo "<div>";
        echo "Result found for keyword: " . $safeKeyword . "<br>";
        echo "Patient: " . $safeName . " | History: " . $safeHistory;
        echo "</div><hr>";
    }
} else {
    echo "No records found for: " . $safeKeyword;
}
?>