#pragma once

#include "stdinc.h"
#include "PluginController.h"
#include "../common/StringUtils.h"

namespace wtwCrypto {
	namespace config {
		static const wchar_t MY_PUB_KEY[] = L"wtwCrypto/myPubKey";
	};
	class SettingsPage {
		HWND		hPanel;

		static INT_PTR CALLBACK dlgProc(HWND, UINT msg, WPARAM, LPARAM) {
			switch(msg) {
				case WM_INITDIALOG: return TRUE;
				case WM_CTLCOLORDLG:
				case WM_CTLCOLORBTN:
				case WM_CTLCOLOREDIT:
				case WM_CTLCOLORSTATIC:
					return bkBrush;
				default: return FALSE;
			}
		}
	public:
		SettingsPage(HWND hParent, HINSTANCE hInst) {
			wtwUtils::Settings* sett = PluginController::getInstance().getSettings();
			sett->read();

			hPanel = CreateDialogW(hInst, MAKEINTRESOURCE(IDD_SETTPAGE), hParent, dlgProc);
			SetDlgItemText(hPanel, IDC_PUBKEY, sett->getWStr(config::MY_PUB_KEY).c_str());
		}

		inline void move(int x, int y, int cx, int cy) {
			MoveWindow(hPanel, x, y, cx, cy, TRUE);
		}

		inline void show() {
			ShowWindow(hPanel, SW_SHOW);
		}

		inline void hide() {
			ShowWindow(hPanel, SW_HIDE);
		}

		void apply() {
			wtwUtils::Settings* sett = PluginController::getInstance().getSettings();
			sett->read();

			std::wstring newMail = strUtils::getDlgItemTextWideStr(hPanel, IDC_PUBKEY);
			if(sett->getWStr(config::MY_PUB_KEY) != newMail) {
				sett->setStr(config::MY_PUB_KEY, newMail.c_str());
				sett->write();
			}
		}

		inline void cancel() {
		}

		~SettingsPage() {
			DestroyWindow(hPanel);
		}
	};
};
