<?php
/**
 * MasterQueryHandler.php
 * ----------------------
 * Production-ready, secure query handler for PHP projects.
 *
 * Features:
 * 1. CRUD operations: insert(), update(), selectOne(), selectAll(), delete()
 * 2. Flexible customQuery() for JOIN, GROUP BY, or any complex SQL (with bound params)
 * 3. Security: Prepared statements, column escaping, table whitelist
 * 4. Safe ORDER BY via whitelist of columns/functions
 * 5. Logging & Debugging: Optional debug flag, sensitive data masking
 * 6. Password helpers: hashPassword(), verifyPassword()
 */

class MasterQueryHandler {
    private $conn;             // mysqli connection object
    private $config;           // env.php config array
    private $logFile;          // path to log file
    private $debug;            // debug flag
    private $allowedTables;    // whitelist of allowed tables
    private $allowedColumns = []; // whitelist of allowed columns (for ORDER BY)
    private $allowedFuncs = []; // allowed SQL functions

    /**
     * Constructor - initializes DB connection and config
     */
    public function __construct(array $options = []) {
        $this->config = require __DIR__ . '/env.php'; // load default config

        // Optionally override config file path
        if (!empty($options['envPath']) && file_exists($options['envPath'])) {
            $this->config = require $options['envPath'];
        }

        // Override log file or debug flag if provided
        if (!empty($options['logFile'])) $this->config['logFile'] = $options['logFile'];
        if (isset($options['debug'])) $this->config['debug'] = (bool)$options['debug'];

        $this->logFile = $this->config['logFile'] ?? (__DIR__ . '/../logs/mqh_secure.log');
        $this->debug = $this->config['debug'] ?? false;
        $this->allowedTables = $this->config['allowedTables'] ?? [];
        $this->allowedColumns = $this->config['allowedColumns'] ?? [];

        $db = $this->config['db'] ?? [];
        $host = $db['host'] ?? 'localhost';
        $user = $db['user'] ?? 'db_user';
        $pass = $db['pass'] ?? 'db_password';
        $name = $db['name'] ?? 'db_name';
        $port = $db['port'] ?? 3306;

        // Enable mysqli exceptions
        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

        try {
            $this->conn = new mysqli($host, $user, $pass, $name, $port);
            $this->conn->set_charset('utf8mb4'); // support full UTF-8
        } catch (Exception $e) {
            $this->writeLog("DB connection failed: " . $e->getMessage());
            throw new RuntimeException('Database connection failed');
        }
    }

    /* =================== CRUD METHODS =================== */

    /**
     * INSERT a row into table
     */
    public function insert($table, array $data, $print = false) {
        try {
            $this->checkTable($table); // check table whitelist
            if (empty($data)) throw new InvalidArgumentException('Data required for insert');

            // Escape column names
            $columnsSql = $this->escapeColumns(array_keys($data));
            $placeholders = implode(', ', array_fill(0, count($data), '?'));

            $sql = "INSERT INTO `$table` ($columnsSql) VALUES ($placeholders)";
            $stmt = $this->conn->prepare($sql);

            // Bind parameters dynamically
            $this->bindParams($stmt, array_values($data));
            $stmt->execute();

            $this->logDebug($sql, array_values($data), 'INSERT', $print);

            return [
                'status' => 1,
                'insert_id' => $this->conn->insert_id,
                'affected_rows' => $stmt->affected_rows
            ];
        } catch (Exception $e) {
            $this->logError('Insert', $sql ?? '', $e->getMessage(), $print);
            return ['status' => 0, 'error' => 'Internal server error'];
        }
    }

    /**
     * UPDATE rows in table
     */
    public function update($table, array $data, $where, array $paramsWhere = [], $print = false) {
        try {
            $this->checkTable($table);
            if (empty($where)) throw new InvalidArgumentException('WHERE required for update');
            if (empty($data)) throw new InvalidArgumentException('Data required for update');

            // Set clause
            $set = implode(', ', array_map(fn($k) => "`$k` = ?", array_keys($data)));
            $sql = "UPDATE `$table` SET $set WHERE $where";

            $params = array_merge(array_values($data), $paramsWhere);
            $stmt = $this->conn->prepare($sql);
            $this->bindParams($stmt, $params);
            $stmt->execute();

            $this->logDebug($sql, $params, 'UPDATE', $print);

            return ['status' => 1, 'affected_rows' => $stmt->affected_rows];
        } catch (Exception $e) {
            $this->logError('Update', $sql ?? '', $e->getMessage(), $print);
            return ['status' => 0, 'error' => 'Internal server error'];
        }
    }

    /**
     * SELECT one row from table
     */
    public function selectOne($table, $columns = '*', $where = '', array $params = [], $print = false) {
        try {
            $this->checkTable($table);
            $sql = "SELECT $columns FROM `$table`" . ($where ? " WHERE $where" : "") . " LIMIT 1";
            $stmt = $this->conn->prepare($sql);
            if (!empty($params)) $this->bindParams($stmt, $params);
            $stmt->execute();

            $row = $stmt->get_result()->fetch_assoc();
            $this->logDebug($sql, $params, 'SELECT ONE', $print);

            return ['status' => 1, 'data' => $row ?: null];
        } catch (Exception $e) {
            $this->logError('SelectOne', $sql ?? '', $e->getMessage(), $print);
            return ['status' => 0, 'error' => 'Internal server error'];
        }
    }

    /**
     * SELECT multiple rows from table
     * Safe ORDER BY and LIMIT
     */
    public function selectAll($table, $columns = '*', $where = '', array $params = [], $orderBy = '', $limit = '', $print = false) {
        try {
            $this->checkTable($table);

            // Sanitize ORDER BY against whitelist
            if ($orderBy !== '') $orderBy = $this->sanitizeOrderBy($orderBy);
            if ($limit !== '' && !$this->validateLimit($limit)) throw new InvalidArgumentException('Invalid LIMIT');

            $sql = "SELECT $columns FROM `$table`"
                 . ($where ? " WHERE $where" : "")
                 . ($orderBy ? " ORDER BY $orderBy" : "")
                 . ($limit ? " LIMIT $limit" : "");

            $stmt = $this->conn->prepare($sql);
            if (!empty($params)) $this->bindParams($stmt, $params);
            $stmt->execute();

            $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
            $this->logDebug($sql, $params, 'SELECT ALL', $print);

            return ['status' => 1, 'data' => $rows];
        } catch (Exception $e) {
            $this->logError('SelectAll', $sql ?? '', $e->getMessage(), $print);
            return ['status' => 0, 'error' => 'Internal server error'];
        }
    }

    /**
     * DELETE rows from table
     */
    public function delete($table, $where, array $params = [], $print = false) {
        try {
            $this->checkTable($table);
            if (empty($where)) throw new InvalidArgumentException('WHERE required for delete');

            $sql = "DELETE FROM `$table` WHERE $where";
            $stmt = $this->conn->prepare($sql);
            if (!empty($params)) $this->bindParams($stmt, $params);
            $stmt->execute();

            $this->logDebug($sql, $params, 'DELETE', $print);

            return ['status' => 1, 'affected_rows' => $stmt->affected_rows];
        } catch (Exception $e) {
            $this->logError('Delete', $sql ?? '', $e->getMessage(), $print);
            return ['status' => 0, 'error' => 'Internal server error'];
        }
    }

    /**
     * Execute any custom query (safe only with bound parameters)
     */
    public function customQuery($sql, array $params = [], $print = false) {
        try {
            $stmt = $this->conn->prepare($sql);
            $this->bindParams($stmt, $params);
            $stmt->execute();

            $resultType = strtoupper(strtok(trim($sql), " "));
            $data = ($resultType === 'SELECT' || $resultType === 'SHOW') 
                ? $stmt->get_result()->fetch_all(MYSQLI_ASSOC) 
                : ['affected_rows' => $stmt->affected_rows];

            $this->logDebug($sql, $params, 'CUSTOM QUERY', $print);

            return ['status' => 1, 'data' => $data];
        } catch (Exception $e) {
            $this->logError('CustomQuery', $sql ?? '', $e->getMessage(), $print);
            return ['status' => 0, 'error' => 'Internal server error'];
        }
    }

    /* =================== HELPER METHODS =================== */

    /**
     * Check if table is allowed
     */
    private function checkTable($table) {
        if (!in_array($table, $this->allowedTables, true)) 
            throw new InvalidArgumentException('Invalid table name');
    }

    /**
     * Escape column names (for INSERT / UPDATE)
     */
    private function escapeColumns(array $cols) {
        return implode(', ', array_map(fn($c) => "`" . preg_replace('/[^a-zA-Z0-9_]/', '', $c) . "`", $cols));
    }

    /**
     * Bind params dynamically to prepared statement
     */
    private function bindParams($stmt, array $values) {
        if (empty($values)) return;

        $types = '';
        foreach ($values as $v) $types .= is_int($v) ? 'i' : (is_float($v) ? 'd' : 's');

        $refs = [];
        foreach ($values as $k => $v) $refs[$k] = &$values[$k];

        array_unshift($refs, $types);

        if (!call_user_func_array([$stmt, 'bind_param'], $refs)) {
            throw new RuntimeException('Parameter binding failed');
        }
    }

    /**
     * Log debug SQL and parameters
     */
    private function logDebug($sql, array $values, $context = '', $print = false) {
        $safeValues = array_map(fn($v) => preg_match('/password|token/i', $v) ? '******' : $v, $values);
        $safeSql = $this->debugPrintSafe($sql, $safeValues);
        $entry = "[" . date('Y-m-d H:i:s') . "] DEBUG {$context}\n" . $safeSql . "\n\n";
        if ($this->debug) $this->writeLog($entry);
        if ($print) echo nl2br($entry);
    }

    /**
     * Log errors with masked sensitive data
     */
    private function logError($context, $sql, $errorMsg, $print = false) {
        $maskedSql = preg_replace('/password\s*=\s*["\'].*?["\']/', 'password=******', $sql);
        $entry  = "[" . date('Y-m-d H:i:s') . "] $context failed:\n";
        $entry .= "SQL => $maskedSql\n";
        $entry .= "Error => $errorMsg\n\n";
        if ($this->debug) $this->writeLog($entry);
        if ($print) echo nl2br($entry);
    }

    /**
     * Replace ? with escaped parameters for debug
     */
    private function debugPrintSafe($sql, array $values) {
        foreach ($values as $v) $sql = preg_replace('/\\?/', "'" . $this->conn->real_escape_string((string)$v) . "'", $sql, 1);
        return $sql;
    }

    /**
     * Write logs to file
     */
    private function writeLog($text) {
        $dir = dirname($this->logFile);
        if (!is_dir($dir)) @mkdir($dir, 0750, true);
        @file_put_contents($this->logFile, $text, FILE_APPEND | LOCK_EX);
    }

    /* =================== ORDER BY & LIMIT =================== */

    /**
     * Sanitize ORDER BY clause
     * Only allow allowed columns/functions
     */
    private function sanitizeOrderBy(string $orderBy): string {
        $parts = explode(',', $orderBy);
        $safeParts = [];
        foreach ($parts as $part) {
            $part = trim($part);
            if (preg_match('/\s+(ASC|DESC)$/i', $part, $matches)) {
                $direction = strtoupper($matches[1]);
                $colFunc = trim(str_ireplace($matches[0], '', $part));
            } else {
                $direction = '';
                $colFunc = $part;
            }

            // Check function usage
            if (preg_match('/^([a-zA-Z0-9_]+)\(([^)]*)\)$/', $colFunc, $m)) {
                $func = strtoupper($m[1]);
                $arg = $m[2];
                if (!in_array($func, $this->allowedFuncs, true)) throw new InvalidArgumentException("Invalid function in ORDER BY");
                if (!in_array($arg, $this->allowedColumns, true)) throw new InvalidArgumentException("Invalid column in ORDER BY function");
                $safeParts[] = "$func(`$arg`)" . ($direction ? " $direction" : '');
            } else {
                if (!in_array($colFunc, $this->allowedColumns, true)) throw new InvalidArgumentException("Invalid column in ORDER BY");
                $safeParts[] = "`$colFunc`" . ($direction ? " $direction" : '');
            }
        }
        return implode(', ', $safeParts);
    }

    /**
     * Validate LIMIT clause
     */
    private function validateLimit($limit) {
        return (bool) preg_match('/^\d+(\s*,\s*\d+)?$/', $limit);
    }

    /* =================== PASSWORD HELPERS =================== */

    public static function hashPassword($plain) {
        return password_hash($plain, PASSWORD_DEFAULT);
    }

    public static function verifyPassword($plain, $hash) {
        return password_verify($plain, $hash);
    }

    /**
     * Close DB connection
     */
    public function close() {
        if ($this->conn) $this->conn->close();
    }
}
