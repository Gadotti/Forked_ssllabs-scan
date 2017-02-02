REPORT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{{VAR_TITLE}}</title>
  <style>
body {
  background:#F4F4F4;
  color:#009ACE;
  font-family:Helvetica, sans-serif, Arial;
  padding:0em 0em 1em 1em;
  text-align:left;
}
.tftable {
  border-collapse:collapse;
  border-color:white;
  color:#333333;
  font-size:15px;
  font-weight:bold;
}
.tftable th {
  background-color:#777777;
  border-color:white;
  border-style:solid;
  border-width:1px;
  color:white;
  padding:8px;
  text-align:left;
}
.tftable tr.A {
  color:green;
}
.tftable tr.B, tr.C, tr.D {
  color:darkorange;
}
.tftable tr.E, tr.F {
  color:red;
}
.tftable tr {
  background-color:#eeeeee;
}
.tftable tr:hover {
  background-color:lightblue;
}
.tftable td {
  border-color:white;
  border-style:solid;
  border-width:1px;
  padding:8px;
}
  </style>
</head>
<body>
<h1>{{VAR_TITLE}}</h1>
<table class="tftable" border="1">
{{VAR_DATA}}
</table>
</body>
</html>
"""
