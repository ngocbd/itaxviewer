package seatechit.ihtkk.tool.hquanform1;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import seatechit.ihtkk.tool.ConfigInfo;
import seatechit.ihtkk.tool.ITaxViewerException;

import seatechit.ihtkk.tool.taxdoc.HSoThue;
import seatechit.ihtkk.tool.taxdoc.PLuc;

public class HquanForm1 extends HSoThue {
	public HquanForm1(Document tkhaiDoc, String tkhaiFileName, ConfigInfo config)
			throws IOException, ParserConfigurationException, ITaxViewerException {
		super(tkhaiDoc, tkhaiFileName, config);
		DMucHquan1 dmucHquan = config.getDmHquan1();
		String nodeName = null;
		if (this.prefix != null) {
			nodeName = this.prefix + ":" + "MA_LH_XNK";
		} else {
			nodeName = "MA_LH_XNK";
		}
		Node node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
		if (node == null) {
			throw new ITaxViewerException("C?u tr�c t?p h? s? kh�ng ?�ng: kh�ng c� th? d? li?u 'MA_LH_XNK'");
		}
		this.maHSo = node.getTextContent();
		if (this.prefix != null) {
			nodeName = this.prefix + ":" + "PBAN_XML";
		} else {
			nodeName = "PBAN_XML";
		}
		node = tkhaiDoc.getElementsByTagName(nodeName).item(0);
		if (node == null) {
			this.pbanHSoXML = "1.0.0";
		}
		if (node != null) {
			this.pbanHSoXML = node.getTextContent();
		}
		this.xsdFile = dmucHquan.getXSDTBao(this.maHSo, this.pbanHSoXML);
		if (this.xsdFile == null) {
			throw new ITaxViewerException(
					"M� Th�ng b�o (" + this.maHSo + ") ho?c phi�n b?n th�ng b�o (" + this.pbanHSoXML + ") kh�ng ?�ng");
		}
		this.viewMethod = dmucHquan.getTBaoViewType(this.maHSo, this.pbanHSoXML);

		this.excelFile = dmucHquan.getExcelTemplateTTBao(this.maHSo, this.pbanHSoXML);

		this.xsltFile = dmucHquan.getXSLTTBao(this.maHSo, this.pbanHSoXML);

		this.orientation = dmucHquan.getTKhaiOrientation(this.maHSo, this.pbanHSoXML);

		this.plucList = getPLucList(dmucHquan);

		Iterator ito = this.sigValidationResult.iterator();

		ArrayList resultArr = new ArrayList();

		this.sigValidationResult = resultArr;

		this.hsoViewFileName = createTemFileForView();
	}

	private String createTemFileForView() throws ITaxViewerException, IOException {
		String defaultNamespace = "xmlns=\"http://kekhaithue.gdt.gov.vn/TKhaiThue\"";
		String content = FileUtils.readFileToString(new File(this.hsoFileName), "UTF-8");
		content = content.replaceAll(defaultNamespace, "");

		String baseFileName = FilenameUtils.getBaseName(this.hsoFileName);
		File tempfile = File.createTempFile(baseFileName, ".tmp");
		tempfile.deleteOnExit();
		FileUtils.writeStringToFile(tempfile, content, "UTF-8");

		return tempfile.getAbsolutePath();
	}

	private Collection getPLucList(DMucHquan1 dmTBao) {
		ArrayList collPLuc = new ArrayList();
		String plucNodeName = "PLuc";
		if (this.prefix != null) {
			plucNodeName = this.prefix + ":" + plucNodeName;
		}
		Node plucNode = this.tkhaiDoc.getElementsByTagName(plucNodeName).item(0);
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

				if (plucIDWithPrefix.length == 1) {
					plucID = plucIDWithPrefix[0];
				} else {
					plucID = plucIDWithPrefix[1];
				}
				pluc.setPlucID(plucID);
				pluc.setPlucName(dmTBao.getTenPLuc(this.maHSo, this.pbanHSoXML, plucID));
				pluc.setPlucViewMethod(dmTBao.getPLucViewType(this.maHSo, this.pbanHSoXML, plucID));
				pluc.setOrientation(dmTBao.getPLucOrientation(this.maHSo, this.pbanHSoXML, plucID));
				pluc.setPlucExcelFile(dmTBao.getExcelTemplatePLuc(this.maHSo, this.pbanHSoXML, plucID));
				pluc.setPlucXSLTFile(dmTBao.getXSLTPLuc(this.maHSo, this.pbanHSoXML, plucID));

				collPLuc.add(pluc);
			}
		}
		return collPLuc;
	}
}
