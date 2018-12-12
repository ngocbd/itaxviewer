package seatechit.ihtkk.tool.taxdoc;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import seatechit.ihtkk.tool.ConfigInfo;
import seatechit.ihtkk.tool.ITaxViewerException;
import seatechit.ihtkk.tool.hquanform.HquanForm;
import seatechit.ihtkk.tool.hquanform1.HquanForm1;
import seatechit.ihtkk.tool.taxCatalog.DMuc;
import seatechit.ihtkk.tool.taxMessage.TBaoThue;
import seatechit.ihtkk.tool.taxMessageNtdt.TBaoThueNtdt;
import seatechit.ihtkk.tool.taxRegistration.DKyThue;
import seatechit.ihtkk.tool.taxmessagekdtt.BKeKDTT;
import seatechit.ihtkk.tool.taxmessagekdtt.TBaoKDTT;
import seatechit.ihtkk.tool.taxreturn.TKhaiThue;
import seatechit.ihtkk.tool.taxvoucher.GNTNSNN;

public abstract class HSoThueFactory
{
  private static final String TKHAI_ROOT_TAG_NAME = "HSoThueDTu";
  private static final String CTU_ROOT_TAG_NAME = "CHUNGTU";
  private static final String TBAO_ROOT_TAG_NAME = "TBaoThueDTu";
  private static final String TBAONtdt_ROOT_TAG_NAME = "THONGBAO";
  private static final String TBAONtdt_ROOT_TAG_NAME1 = "TBAO_TKHOAN_NH";
  private static final String TBAONtdt_ROOT_TAG_NAME2 = "TBAO_TKHOAN_NT";
  private static final String TBAONtdt_ROOT_TAG_NAME3 = "TBAO_NGUNG";
  private static final String TBAONtdt_ROOT_TAG_NAME4 = "THONG_BAO";
  private static final String DMUC_TAG_NAME = "DanhMucDTu";
  private static final String HSODKY_TAG_NAME = "DKyThueDTu";
  private static final String HQuan_TAG_NAME = "TOKHAI_OBJ";
  private static final String HQuan_TAG_NAME_2 = "TOKHAISUA_OBJ";
  private static final String TBAO_KDTT_ROOT_TAG_NAME = "THONGBAO";
  private static final String BKE_KDTT_ROOT_TAG_NAME = "BKE_TBAO";

  static Document hsoDoc=null;
  public static HSoThue createHSoThue(String tkhaiFileName, ConfigInfo config)
    throws IOException, ParserConfigurationException, ITaxInvalidDocException, ITaxViewerException
  {  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    
    dbf.setNamespaceAware(true);
    DocumentBuilder db = dbf.newDocumentBuilder();
    File fTKhai = new File(tkhaiFileName);
    try
    {
       hsoDoc = db.parse(fTKhai);
    }
    catch (Exception se)
    {
      
      se.printStackTrace();
      throw new ITaxInvalidDocException("T?p h? s? kh�ng ?�ng ??nh d?ng.");
    }
    
    Element rootElm = hsoDoc.getDocumentElement();
    if (rootElm.getTagName().equals("HSoThueDTu")) {
      return new TKhaiThue(hsoDoc, tkhaiFileName, config);
    }
    if (rootElm.getTagName().equals("TBaoThueDTu")) {
      return new TBaoThue(hsoDoc, tkhaiFileName, config);
    }
    if (rootElm.getTagName().equals("CHUNGTU")) {
      return new GNTNSNN(hsoDoc, tkhaiFileName, config);
    }
    if ((rootElm.getTagName().equals("THONGBAO")) || 
      (rootElm.getTagName().equals("TBAO_TKHOAN_NH")) || 
      (rootElm.getTagName().equals("TBAO_TKHOAN_NT")) || 
      (rootElm.getTagName().equals("TBAO_NGUNG")) || 
      (rootElm.getTagName().equals("THONG_BAO"))) {
      return new TBaoThueNtdt(hsoDoc, tkhaiFileName, config);
    }
    if (rootElm.getTagName().equals("DanhMucDTu")) {
      return new DMuc(hsoDoc, tkhaiFileName, config);
    }
    if (rootElm.getTagName().equals("DKyThueDTu")) {
      return new DKyThue(hsoDoc, tkhaiFileName, config);
    }
    if (rootElm.getTagName().equals("TOKHAI_OBJ")) {
      return new HquanForm(hsoDoc, tkhaiFileName, config);
    }
    if (rootElm.getTagName().equals("TOKHAISUA_OBJ")) {
      return new HquanForm1(hsoDoc, tkhaiFileName, config);
    }
    if (rootElm.getTagName().equals("BKE_TBAO")) {
      return new BKeKDTT(hsoDoc, tkhaiFileName, config);
    }
    throw new ITaxInvalidDocException("T?p h? s? kh�ng ?�ng ??nh d?ng.");
  }
  
  public static HSoThue createHSoThueByText(String contentData, ConfigInfo config)
    throws IOException, ParserConfigurationException, ITaxInvalidDocException, ITaxViewerException
  {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    DocumentBuilder db = dbf.newDocumentBuilder();
    try
    {
      InputSource is = new InputSource(new StringReader(contentData));
      hsoDoc = db.parse(is);
    }
    catch (Exception se)
    {
      Document hsoDoc;
      se.printStackTrace();
      throw new ITaxInvalidDocException("D? li?u h? s? kh�ng ?�ng ??nh d?ng.");
    }
    Document hsoDoc = null;
    Element rootElm = hsoDoc.getDocumentElement();
    if (rootElm.getTagName().equals("THONGBAO")) {
      return new TBaoKDTT(hsoDoc, "", config);
    }
    throw new ITaxInvalidDocException("T?p h? s? kh�ng ?�ng ??nh d?ng.");
  }
}
