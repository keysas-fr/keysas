<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:cdx="http://cyclonedx.org/schema/bom/1.3"
    exclude-result-prefixes="cdx">
    
  <xsl:output method="html" indent="yes" encoding="UTF-8"/>

  <xsl:template match="/">
    <html>
      <head>
        <title>SBOM Viewer - CycloneDX</title>
        <style>
          body { font-family: sans-serif; margin: 2em; }
          table { border-collapse: collapse; width: 100%; }
          th, td { border: 1px solid #ccc; padding: 8px; }
          th { background-color: #f4f4f4; }
        </style>
      </head>
      <body>
        <h1>Software Bill of Materials (CycloneDX)</h1>
        <table>
          <thead>
            <tr>
              <th>Nom</th>
              <th>Version</th>
              <th>Description</th>
              <th>Licence</th>
              <th>URL</th>
            </tr>
          </thead>
          <tbody>
            <xsl:for-each select="//cdx:component">
              <tr>
                <td><xsl:value-of select="cdx:name"/></td>
                <td><xsl:value-of select="cdx:version"/></td>
                <td><xsl:value-of select="cdx:description"/></td>
                <td><xsl:value-of select="cdx:licenses/cdx:expression"/></td>
                <td>
                  <xsl:for-each select="cdx:externalReferences/cdx:reference[1]/cdx:url">
                    <a href="{.}" target="_blank"><xsl:value-of select="."/></a>
                  </xsl:for-each>
                </td>
              </tr>
            </xsl:for-each>
          </tbody>
        </table>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>

