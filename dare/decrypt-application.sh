printf "Decrypting application\n"

decrypt-application \
  --decrypted-application "{{.decryptedApplication}}" \
  --encrypted-application "{{.encryptedApplication}}" \
  --salt "{{.salt}}"
