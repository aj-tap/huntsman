#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "-----------------------------------------------------------------------"
echo "Running pre-flight checks..."
echo "-----------------------------------------------------------------------"

echo "Running pydocstyle..."
# We allow pydocstyle to fail (just warn) so it doesn't block the build
if python3 -m pydocstyle --convention=numpy api/; then
    echo "Docstyle checks passed."
else
    echo "WARNING: Docstyle found issues. Proceeding with build."
fi

echo "-----------------------------------------------------------------------"
echo "Cleaning environment..."
echo "-----------------------------------------------------------------------"
rm -rf docs/_build
rm -f docs/api.rst
rm -f docs/modules.rst
rm -f docs/huntsman.rst
rm -rf docs/api/ 
rm -rf docs/images

echo "-----------------------------------------------------------------------"
echo "Preparing assets..."
echo "-----------------------------------------------------------------------"
mkdir -p docs/_static

mkdir -p docs/images
echo "Copying icons to documentation source..."
cp -r api/static/api/icons docs/images/

echo "-----------------------------------------------------------------------"
echo "Compiling HTML..."
echo "-----------------------------------------------------------------------"
# -W: Turn warnings into errors
# --keep-going: Show all errors before stopping
sphinx-build -W --keep-going -b html docs docs/_build/html

echo "-----------------------------------------------------------------------"
echo "Documentation built successfully!"
echo "Open docs/_build/html/index.html to view."
echo "-----------------------------------------------------------------------"