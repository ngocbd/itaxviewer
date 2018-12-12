package seatechit.ihtkk.tool.taxmessagekdtt;

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




public class BKeKDTT
  extends HSoThue
{
  public BKeKDTT(Document tkhaiDoc, String tkhaiFileName, ConfigInfo config)
    throws IOException, ParserConfigurationException, ITaxViewerException
  {
    super(tkhaiDoc, tkhaiFileName, config);
    DMucBKeKDTT dmBKeKDTT = config.getDmBKeKDTT();
    String nodeName = null;
    

    if (prefix != null) {
      nodeName = prefix + ":" + "MA_THONGBAO";
    } else {
      nodeName = "MA_THONGBAO";
    }
    Node node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
    if (node == null) {
      if (prefix != null) {
        nodeName = prefix + ":" + "MA_BK";
      } else {
        nodeName = "MA_BK";
      }
      node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
    }
    if (node == null) {
      throw new ITaxViewerException(
        "Cấu trúc tệp hồ sơ không đúng: không có thẻ dữ liệu 'MA_THONGBAO'");
    }
    maHSo = node.getTextContent();
    
    if (prefix != null) {
      nodeName = prefix + ":" + "PBAN_TLIEU_XML";
    } else {
      nodeName = "PBAN_TLIEU_XML";
    }
    node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
    if (node == null) {
      pbanHSoXML = "4.0.0";
    } else {
      pbanHSoXML = node.getTextContent();
    }
    
    if (pbanHSoXML.equals("")) {
      pbanHSoXML = "4.0.0";
    }
    
    xsdFile = dmBKeKDTT.getXSDTBao(maHSo, pbanHSoXML);
    if (xsdFile == null) {
      throw new ITaxViewerException("Mã Bảng kê (" + maHSo + 
        ") hoặc phiên bản Bảng kê (" + pbanHSoXML + 
        ") không đúng");
    }
    
    viewMethod = dmBKeKDTT.getTBaoViewType(maHSo, pbanHSoXML);
    
    excelFile = dmBKeKDTT.getExcelTemplateTTBao(maHSo, pbanHSoXML);
    
    xsltFile = dmBKeKDTT.getXSLTTBao(maHSo, pbanHSoXML);
    
    orientation = dmBKeKDTT.getTKhaiOrientation(maHSo, pbanHSoXML);
    
    plucList = getPLucList(dmBKeKDTT);
    

    sigValidationResult = new IHTKKXMLSignature(config.getRootCerts(), 
      config.getTrustedCerts()).verifyXMLSignature(tkhaiDoc);
    


    hsoViewFileName = createTemFileForView();
  }
  

  private String createTemFileForView()
    throws ITaxViewerException, IOException
  {
    String defaultNamespace = "xmlns=\"http://kekhaithue.gdt.gov.vn/TKhaiThue\"";
    String content = FileUtils.readFileToString(new File(hsoFileName), 
      "UTF-8");
    content = content.replaceAll(defaultNamespace, "");
    
    String baseFileName = FilenameUtils.getBaseName(hsoFileName);
    File tempfile = File.createTempFile(baseFileName, ".tmp");
    tempfile.deleteOnExit();
    FileUtils.writeStringToFile(tempfile, content, "UTF-8");
    
    return tempfile.getAbsolutePath();
  }
  
  private Collection getPLucList(DMucBKeKDTT dmBKeKDTT) {
    ArrayList collPLuc = new ArrayList();
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
        String[] plucIDWithPrefix = plucList.item(i).getNodeName()
          .split(":");
        String plucID;
        String plucID; if (plucIDWithPrefix.length == 1) {
          plucID = plucIDWithPrefix[0];
        } else {
          plucID = plucIDWithPrefix[1];
        }
        pluc.setPlucID(plucID);
        pluc.setPlucName(dmBKeKDTT.getTenPLuc(maHSo, pbanHSoXML, plucID));
        pluc.setPlucViewMethod(dmBKeKDTT.getPLucViewType(maHSo, 
          pbanHSoXML, plucID));
        pluc.setOrientation(dmBKeKDTT.getPLucOrientation(maHSo, 
          pbanHSoXML, plucID));
        pluc.setPlucExcelFile(dmBKeKDTT.getExcelTemplatePLuc(maHSo, 
          pbanHSoXML, plucID));
        pluc.setPlucXSLTFile(dmBKeKDTT.getXSLTPLuc(maHSo, pbanHSoXML, 
          plucID));
        
        collPLuc.add(pluc);
      }
    }
    return collPLuc;
  }
}
