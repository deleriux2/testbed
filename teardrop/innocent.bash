#!/bin/bash
cat <<EOF >target.bash
#!/bin/bash
echo "I am innocent"
EOF

bash target.bash
