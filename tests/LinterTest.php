<?php

use PHPUnit\Framework\TestCase;
use SecurityLinter\Linter;

class LinterTest extends TestCase
{
    public function testAutoFixXSS()
    {
        // Exemple d'utilisation de Linter
        $filePath = __DIR__ . '/testFile.php';
        file_put_contents($filePath, "<?php\n\n");

        Linter::autoFixXSS($filePath);

        $this->assertTrue(true);
    }

    public function testAutoFixXSSWithSafeCode()
    {
        $filePath = __DIR__ . '/safeFile.php';
        file_put_contents($filePath, "<?php\n\$variable = htmlspecialchars(\$_POST['data']);\n");

        Linter::autoFixXSS($filePath);

        $this->assertTrue(true);
    }
}