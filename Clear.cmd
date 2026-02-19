@ECHO OFF

FOR /D %%d IN (*) DO (
  PUSHD %CD%\%%d
	IF EXIST %CD%\%%d\Clear.cmd (
      ECHO ************ Run Clear %CD%\%%d ******************
      CALL Clear.cmd 
	)
  POPD
)

@ECHO ON
pause