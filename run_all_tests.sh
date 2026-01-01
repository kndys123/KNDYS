#!/bin/bash
# run_all_tests.sh - Ejecutar todos los tests generados

echo "🧪 Ejecutando suite completa de tests KNDYS..."
echo "================================================"
echo ""

PASS_COUNT=0
FAIL_COUNT=0
ERROR_COUNT=0
TOTAL_COUNT=0

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Ejecutar cada test
for test_file in test_*.py; do
    if [ -f "$test_file" ]; then
        echo -n "Testing $test_file... "
        TOTAL_COUNT=$((TOTAL_COUNT + 1))
        
        # Ejecutar test y capturar resultado
        if python3 "$test_file" > /tmp/test_output.log 2>&1; then
            # Contar tests pasados
            tests_run=$(grep -c "^test_" /tmp/test_output.log || echo "0")
            echo -e "${GREEN}✓ PASS${NC} ($tests_run tests)"
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            # Ver si hay errores o fallos
            if grep -q "ERROR" /tmp/test_output.log; then
                echo -e "${RED}✗ ERROR${NC}"
                ERROR_COUNT=$((ERROR_COUNT + 1))
            else
                echo -e "${YELLOW}✗ FAIL${NC}"
                FAIL_COUNT=$((FAIL_COUNT + 1))
            fi
            
            # Mostrar últimas líneas del error
            echo "  $(tail -3 /tmp/test_output.log | head -1)"
        fi
    fi
done

echo ""
echo "================================================"
echo "📊 RESULTADOS:"
echo "================================================"
echo "Total test files: $TOTAL_COUNT"
echo -e "${GREEN}Passed: $PASS_COUNT${NC}"
echo -e "${YELLOW}Failed: $FAIL_COUNT${NC}"
echo -e "${RED}Errors: $ERROR_COUNT${NC}"
echo ""

# Calcular porcentaje de éxito
if [ $TOTAL_COUNT -gt 0 ]; then
    SUCCESS_RATE=$(echo "scale=1; $PASS_COUNT * 100 / $TOTAL_COUNT" | bc)
    echo "Success rate: $SUCCESS_RATE%"
fi

echo ""
echo "================================================"

# Generar reporte detallado
cat > TEST_EXECUTION_REPORT.md << EOF
# Test Execution Report

**Date**: $(date)  
**Test Files Executed**: $TOTAL_COUNT

## Results Summary

| Status | Count | Percentage |
|--------|-------|------------|
| ✅ Passed | $PASS_COUNT | ${SUCCESS_RATE}% |
| ⚠️  Failed | $FAIL_COUNT | $(echo "scale=1; $FAIL_COUNT * 100 / $TOTAL_COUNT" | bc)% |
| ❌ Errors | $ERROR_COUNT | $(echo "scale=1; $ERROR_COUNT * 100 / $TOTAL_COUNT" | bc)% |

## Test Files Status

EOF

# Añadir estado de cada test al reporte
for test_file in test_*.py; do
    if [ -f "$test_file" ]; then
        if python3 "$test_file" > /tmp/test_check.log 2>&1; then
            echo "- ✅ $test_file - PASSED" >> TEST_EXECUTION_REPORT.md
        else
            if grep -q "ERROR" /tmp/test_check.log; then
                echo "- ❌ $test_file - ERROR" >> TEST_EXECUTION_REPORT.md
            else
                echo "- ⚠️  $test_file - FAILED" >> TEST_EXECUTION_REPORT.md
            fi
        fi
    fi
done

cat >> TEST_EXECUTION_REPORT.md << EOF

## Coverage Statistics

- **Test files**: $TOTAL_COUNT
- **Modules with tests**: $(ls test_*.py 2>/dev/null | wc -l)
- **Total KNDYS modules**: 52
- **Coverage**: $(echo "scale=1; $(ls test_*.py 2>/dev/null | wc -l) * 100 / 52" | bc)%

## Next Steps

1. Fix failing tests
2. Implement logic for 'pass' placeholders
3. Add integration tests
4. Measure code coverage with coverage.py

EOF

echo "📄 Detailed report saved to TEST_EXECUTION_REPORT.md"
