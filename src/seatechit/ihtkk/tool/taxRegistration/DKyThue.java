package seatechit.ihtkk.tool.taxRegistration;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import seatechit.ihtkk.tool.ConfigInfo;
import seatechit.ihtkk.tool.ITaxViewerException;
import seatechit.ihtkk.tool.signature.IHTKKXMLSignature;
import seatechit.ihtkk.tool.taxdoc.HSoThue;
import seatechit.ihtkk.tool.taxdoc.PLuc;



public class DKyThue
  extends HSoThue
{
  public DKyThue(Document tkhaiDoc, String tkhaiFileName, ConfigInfo config)
    throws IOException, ParserConfigurationException, ITaxViewerException
  {
    super(tkhaiDoc, tkhaiFileName, config);
    DMucDKy dmDKy = config.getDmDKy();
    String nodeName = null;
    

    if (prefix != null) {
      nodeName = prefix + ":" + "maDKy";
    }
    else {
      nodeName = "maDKy";
    }
    Node node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
    if (node == null) {
      throw new ITaxViewerException("Cấu trúc tệp hồ sơ không đúng: không có thẻ dữ liệu 'maDKy'");
    }
    maHSo = node.getTextContent();
    
    if (prefix != null) {
      nodeName = prefix + ":" + "pBanDKy";
    }
    else {
      nodeName = "pBanDKy";
    }
    node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
    if (node == null) {
      throw new ITaxViewerException("Cấu trúc tệp hồ sơ không đúng: không có thẻ dữ liệu 'pBanDKy'");
    }
    pbanHSoXML = node.getTextContent();
    
    xsdFile = dmDKy.getXSDTBao(maHSo, pbanHSoXML);
    if (xsdFile == null) {
      throw new ITaxViewerException("Mã đăng ký (" + maHSo + ") hoặc phiên bản đăng ký (" + pbanHSoXML + ") không đúng");
    }
    
    viewMethod = dmDKy.getTBaoViewType(maHSo, pbanHSoXML);
    
    excelFile = dmDKy.getExcelTemplateTTBao(maHSo, pbanHSoXML);
    
    xsltFile = dmDKy.getXSLTTBao(maHSo, pbanHSoXML);
    
    orientation = dmDKy.getTKhaiOrientation(maHSo, pbanHSoXML);
    
    plucList = getPLucList(dmDKy);
    

    sigValidationResult = new IHTKKXMLSignature(config.getRootCerts(), config.getTrustedCerts()).verifyXMLSignature(tkhaiDoc, config.getDkyXpath());
    

    hsoViewFileName = createTemFileForView();
  }
  
  private String createTemFileForView() throws ITaxViewerException, IOException
  {
    String defaultNamespace = "xmlns=\"http://kekhaithue.gdt.gov.vn/HSoDKy\"";
    String content = FileUtils.readFileToString(new File(hsoFileName), "UTF-8");
    content = content.replaceAll(defaultNamespace, "");
    
    String baseFileName = FilenameUtils.getBaseName(hsoFileName);
    File tempfile = File.createTempFile(baseFileName, ".tmp");
    tempfile.deleteOnExit();
    FileUtils.writeStringToFile(tempfile, content, "UTF-8");
    
    return tempfile.getAbsolutePath();
  }
  
  private Collection getPLucList(DMucDKy dmTBao) { ArrayList collPLuc = new ArrayList();
    String plucNodeName = "PLuc";
    if (prefix != null) {
      plucNodeName = prefix + ":" + plucNodeName;
    }
    
    Node plucNode = tkhaiDoc.getElementsByTagName(plucNodeName).item(0);
    if (plucNode == null) {
      return null;
    }
    NodeList plucList = plucNode.getChildNodes();
    int len = plucList.getLength();
    for (int i = 0; i < len; i++) {
      if (plucList.item(i).getNodeType() == 1) {
        PLuc pluc = new PLuc();
        String[] plucIDWithPrefix = plucList.item(i).getNodeName().split(":");
        String plucID;
        String plucID; if (plucIDWithPrefix.length == 1) {
          plucID = plucIDWithPrefix[0];
        } else {
          plucID = plucIDWithPrefix[1];
        }
        pluc.setPlucID(plucID);
        pluc.setPlucName(dmTBao.getTenPLuc(maHSo, pbanHSoXML, plucID));
        pluc.setPlucViewMethod(dmTBao.getPLucViewType(maHSo, pbanHSoXML, plucID));
        pluc.setOrientation(dmTBao.getPLucOrientation(maHSo, pbanHSoXML, plucID));
        pluc.setPlucExcelFile(dmTBao.getExcelTemplatePLuc(maHSo, pbanHSoXML, plucID));
        pluc.setPlucXSLTFile(dmTBao.getXSLTPLuc(maHSo, pbanHSoXML, plucID));
        
        collPLuc.add(pluc);
      }
    }
    return collPLuc;
  }
}
