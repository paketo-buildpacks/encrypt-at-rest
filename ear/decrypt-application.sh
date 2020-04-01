printf "Decrypting application\n"

decrypt-application \
  --encrypted-application "{{.encryptedApplication}}" \
  --initial-vector "{{.initialVector}}" \
  --decrypted-application "{{.decryptedApplication}}"
