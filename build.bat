@echo off
setlocal
cd /d "%~dp0"

rem ---------------------------------------------------------------- JDK lookup
set "JAVAC="
set "JAR="
if defined JAVA_HOME (
    if exist "%JAVA_HOME%\bin\javac.exe" (
        set "JAVAC=%JAVA_HOME%\bin\javac.exe"
        set "JAR=%JAVA_HOME%\bin\jar.exe"
        set "JAVABIN=%JAVA_HOME%\bin"
    )
)
if not defined JAVAC (
    for %%d in ("D:\Langs\Java\jdk-21" "C:\Program Files\Java\jdk-21" "C:\Program Files\Java\jdk-17") do (
        if exist "%%~d\bin\javac.exe" (
            set "JAVAC=%%~d\bin\javac.exe"
            set "JAR=%%~d\bin\jar.exe"
            set "JAVABIN=%%~d\bin"
        )
    )
)
if not defined JAVAC (
    echo ERROR: no JDK 17+ found. Install a JDK or set JAVA_HOME.
    exit /b 1
)

rem ------------------------------------------------------- montoya-api library
set "MONTOYA=lib\montoya-api-2025.10.jar"
if not exist "%MONTOYA%" (
    echo Downloading montoya-api-2025.10.jar from Maven Central...
    if not exist lib mkdir lib
    curl.exe -L -f -o "%MONTOYA%" https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2025.10/montoya-api-2025.10.jar
    if errorlevel 1 (
        echo ERROR: download failed. Get the jar from
        echo   https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/
        echo and place it at %MONTOYA%
        exit /b 1
    )
)

rem ------------------------------------------------------------------- compile
if exist build\classes rmdir /s /q build\classes
mkdir build\classes 2>nul
dir /s /b src\main\java\*.java > build\sources.txt
"%JAVAC%" --release 17 -encoding UTF-8 -cp "%MONTOYA%" -d build\classes @build\sources.txt
if errorlevel 1 (
    echo ERROR: compilation failed.
    exit /b 1
)

rem ------------------------------------------------------------- self-test run
"%JAVABIN%\java.exe" -cp build\classes com.ecapture.burp.SelfTest
if errorlevel 1 (
    echo WARNING: self-test reported failures; jar was NOT built.
    exit /b 1
)

rem ---------------------------------------------------------------------- jar
if exist eCapture-burp.jar del eCapture-burp.jar
(
    echo Implementation-Title: eCapture for Burp Suite
    echo Implementation-Vendor: Sunny - https://sunny.onl
    echo Created-By: Sunny - https://sunny.onl
) > build\manifest.txt
"%JAR%" --create --file eCapture-burp.jar --manifest build\manifest.txt -C build\classes .
if errorlevel 1 (
    echo ERROR: jar creation failed.
    exit /b 1
)
del build\sources.txt

echo.
echo Built eCapture-burp.jar - load it in Burp via Extensions -^> Installed -^> Add.
endlocal
