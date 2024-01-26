REPORT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <!-- 30min refresh -->
  <meta http-equiv="refresh" content="1800">
  <title>{{VAR_TITLE}}</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
<h1>{{VAR_TITLE}}</h1>
<h3>Last checked: {{LAST_CHECKED}}</h3>
<a href='summary.csv'>Summary CVS File Download</a>
<table class="tftable" border="1">
{{VAR_DATA}}
</table>
</body>
</html>
"""
