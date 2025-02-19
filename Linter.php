<?php
class Linter{
    private static $rules = [
        'Protection XSS' => '/\$_(GET|POST|REQUEST|COOKIE)\[.*?\](?!.*htmlspecialchars|strip_tags)/',
        'SQL Injection'  => '/mysqli_query\(.*?\$.*?\)/'
    ];

    public static function scanFiles($filePath){
        $issues = [];
        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach($lines as $i => $line){
            foreach(self::$rules as $ruleName => $pattern){
                if(preg_match($pattern, $line)){
                    $issues[] = "$ruleName -> $filePath (Ligne " . ($i + 1) . "): $line";
                }
            }
        }
        return $issues;
    }

    public static function scanProjet($path){
        $issues = [];
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path));

        foreach($files as $file){
            if($file->isFile() && pathinfo($file, PATHINFO_EXTENSION) === 'php'){
                $issues = array_merge($issues, self::scanFiles($file->getPathname()));
            }
        }
        return $issues;
    }
}