<?php
/**
 * env.php
 * ----------------------
 * Environment and DB configuration.
 * Keep this file secure, ideally outside public webroot in production.
 */

return [
    'env' => 'production',        // 'development' or 'production'
    'debug' => true,             // true => debug logs active, false => production safe

    // --- Database Credentials ---
    'db' => [
        'host' => 'localhost',          // DB Host
        'user' => 'deltaitc_wp675',     // DB Username
        'pass' => '3!T3]p38S5',         // DB Password
        'name' => 'deltaitc_wp675',     // DB Name
        'port' => 3306,                 // Optional, default MySQL port
    ],

    // --- Log file path ---
    'logFile' => __DIR__ . '/../logs/mqh_secure.log',

    // --- Allowed Tables ---
    'allowedTables' => [
        'users',
        // Add other tables your project uses
    ],

    // --- Allowed Columns (for ORDER BY or SELECT expressions) ---
    'allowedColumns' => [
        'id',
        'name',
        'email',
        'phone',
        'password',
        'status',
        'created_at',
        'updated_at',
    ],

    // --- Allowed SQL Functions (for ORDER BY / SELECT) ---
    'allowedFuncs' => [
        'LOWER',
        'UPPER',
        'LENGTH',
        'ROUND',
        'TRIM',
        'COALESCE',
        'IFNULL',
        'DATE',
        'DATE_FORMAT',
        'ABS',
    ],
];
?>