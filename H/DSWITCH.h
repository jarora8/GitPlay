main ()
{
  int avar;
  int j = 0;
  EXEC SQL INCLUDE SQLCA;
  switch (avar)
  {
  case '1': EXEC SQL COMMIT WORK;
            break;
  case '2': EXEC SQL COMMIT WORK;
            break;
  }
 }