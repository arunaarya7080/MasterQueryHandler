<?php
/**
 * example.php
 * ----------------------
 * Demonstrates usage of MasterQueryHandler
 *  Folder - config/MasterQueryHandler.php
 *  Folder - config/env.php
 *  Folder - project/index.php
 */
require __DIR__ . '/config/MasterQueryHandler.php';

$db = new MasterQueryHandler();

// ================= INSERT =================
$insertData = [
    'name' => 'arun',
    'email' => 'arun@example.com',
    'phone' => '8070800096',
    'password' => '12345'
];
$insertResult = $db->insert('users', $insertData,true);

echo "<pre>"; print_r($insertResult); echo "</pre>";
