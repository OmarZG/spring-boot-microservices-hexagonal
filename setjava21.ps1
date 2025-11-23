# setjava21.ps1
$env:JAVA_HOME = "C:\Java\jdk-21"
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
Write-Host "Java 21 activated" -ForegroundColor Green
java -version