// SPDX-License-Identifier: GPL-2.0-only
/*
 * Key management related functions.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#include <net/mac80211.h>

#include "wfx.h"
#include "wsm_rx.h"
#include "key.h"

static int wfx_alloc_key(struct wfx_dev *wdev)
{
	int idx;

	idx = ffs(~wdev->key_map) - 1;
	if (idx < 0 || idx > WSM_KEY_MAX_INDEX)
		return -1;

	wdev->key_map |= BIT(idx);
	wdev->keys[idx].EntryIndex = idx;
	return idx;
}

static void wfx_free_key(struct wfx_dev *wdev, int idx)
{
	BUG_ON(!(wdev->key_map & BIT(idx)));
	memset(&wdev->keys[idx], 0, sizeof(wdev->keys[idx]));
	wdev->key_map &= ~BIT(idx);
}

static uint8_t fill_wep_pair(WsmHiWepPairwiseKey_t *msg, struct ieee80211_key_conf *key, u8 *peer_addr)
{
	WARN_ON(key->keylen > sizeof(msg->KeyData));
	msg->KeyLength = key->keylen;
	memcpy(msg->KeyData, key->key, key->keylen);
	ether_addr_copy(msg->PeerAddress, peer_addr);
	return WSM_KEY_TYPE_WEP_PAIRWISE;
}

static uint8_t fill_wep_group(WsmHiWepGroupKey_t *msg, struct ieee80211_key_conf *key)
{
	WARN_ON(key->keylen > sizeof(msg->KeyData));
	msg->KeyId = key->keyidx;
	msg->KeyLength = key->keylen;
	memcpy(msg->KeyData, key->key, key->keylen);
	return WSM_KEY_TYPE_WEP_DEFAULT;
}

static uint8_t fill_tkip_pair(WsmHiTkipPairwiseKey_t *msg, struct ieee80211_key_conf *key, u8 *peer_addr)
{
	uint8_t *keybuf = key->key;

	WARN_ON(key->keylen != sizeof(msg->TkipKeyData) + sizeof(msg->TxMicKey) + sizeof(msg->RxMicKey));
	memcpy(msg->TkipKeyData, keybuf, sizeof(msg->TkipKeyData));
	keybuf += sizeof(msg->TkipKeyData);
	memcpy(msg->TxMicKey, keybuf, sizeof(msg->TxMicKey));
	keybuf += sizeof(msg->TxMicKey);
	memcpy(msg->RxMicKey, keybuf, sizeof(msg->RxMicKey));
	ether_addr_copy(msg->PeerAddress, peer_addr);
	return WSM_KEY_TYPE_TKIP_PAIRWISE;
}

static uint8_t fill_tkip_group(WsmHiTkipGroupKey_t *msg, struct ieee80211_key_conf *key, struct ieee80211_key_seq *seq, enum nl80211_iftype iftype)
{
	uint8_t *keybuf = key->key;

	WARN_ON(key->keylen != sizeof(msg->TkipKeyData) + 2 * sizeof(msg->RxMicKey));
	msg->KeyId = key->keyidx;
	memcpy(msg->RxSequenceCounter, &seq->tkip.iv16, sizeof(seq->tkip.iv16));
	memcpy(msg->RxSequenceCounter + sizeof(uint16_t), &seq->tkip.iv32, sizeof(seq->tkip.iv32));
	memcpy(msg->TkipKeyData, keybuf, sizeof(msg->TkipKeyData));
	keybuf += sizeof(msg->TkipKeyData);
	if (iftype == NL80211_IFTYPE_AP)
		memcpy(msg->RxMicKey, keybuf + 0, sizeof(msg->RxMicKey)); // Use Tx MIC Key
	else
		memcpy(msg->RxMicKey, keybuf + 8, sizeof(msg->RxMicKey)); // Use Rx MIC Key
	return WSM_KEY_TYPE_TKIP_GROUP;
}

static uint8_t fill_ccmp_pair(WsmHiAesPairwiseKey_t *msg, struct ieee80211_key_conf *key, u8 *peer_addr)
{
	WARN_ON(key->keylen != sizeof(msg->AesKeyData));
	ether_addr_copy(msg->PeerAddress, peer_addr);
	memcpy(msg->AesKeyData, key->key, key->keylen);
	return WSM_KEY_TYPE_AES_PAIRWISE;
}

static uint8_t fill_ccmp_group(WsmHiAesGroupKey_t *msg, struct ieee80211_key_conf *key, struct ieee80211_key_seq *seq)
{
	WARN_ON(key->keylen != sizeof(msg->AesKeyData));
	memcpy(msg->AesKeyData, key->key, key->keylen);
	memcpy(msg->RxSequenceCounter, seq->ccmp.pn, sizeof(seq->ccmp.pn));
	memreverse(msg->RxSequenceCounter, sizeof(seq->ccmp.pn));
	msg->KeyId = key->keyidx;
	return WSM_KEY_TYPE_AES_GROUP;
}

static uint8_t fill_sms4_pair(WsmHiWapiPairwiseKey_t *msg, struct ieee80211_key_conf *key, u8 *peer_addr)
{
	uint8_t *keybuf = key->key;

	WARN_ON(key->keylen != sizeof(msg->WapiKeyData) + sizeof(msg->MicKeyData));
	ether_addr_copy(msg->PeerAddress, peer_addr);
	memcpy(msg->WapiKeyData, keybuf, sizeof(msg->WapiKeyData));
	keybuf += sizeof(msg->WapiKeyData);
	memcpy(msg->MicKeyData, keybuf, sizeof(msg->MicKeyData));
	msg->KeyId = key->keyidx;
	return WSM_KEY_TYPE_WAPI_PAIRWISE;
}

static uint8_t fill_sms4_group(WsmHiWapiGroupKey_t *msg, struct ieee80211_key_conf *key)
{
	uint8_t *keybuf = key->key;

	WARN_ON(key->keylen != sizeof(msg->WapiKeyData) + sizeof(msg->MicKeyData));
	memcpy(msg->WapiKeyData, keybuf, sizeof(msg->WapiKeyData));
	keybuf += sizeof(msg->WapiKeyData);
	memcpy(msg->MicKeyData, keybuf, sizeof(msg->MicKeyData));
	msg->KeyId = key->keyidx;
	return WSM_KEY_TYPE_WAPI_GROUP;
}

static uint8_t fill_aes_cmac_group(WsmHiIgtkGroupKey_t *msg, struct ieee80211_key_conf *key, struct ieee80211_key_seq *seq)
{
	WARN_ON(key->keylen != sizeof(msg->IGTKKeyData));
	memcpy(msg->IGTKKeyData, key->key, key->keylen);
	memcpy(msg->IPN, seq->aes_cmac.pn, sizeof(seq->aes_cmac.pn));
	memreverse(msg->IPN, sizeof(seq->aes_cmac.pn));
	msg->KeyId = key->keyidx;
	return WSM_KEY_TYPE_IGTK_GROUP;
}

static int wfx_add_key(struct wfx_vif *wvif, struct ieee80211_sta *sta, struct ieee80211_key_conf *key)
{
	int ret;
	WsmHiAddKeyReqBody_t *k;
	struct ieee80211_key_seq seq;
	struct wfx_dev *wdev = wvif->wdev;
	int idx = wfx_alloc_key(wvif->wdev);
	bool pairwise = key->flags & IEEE80211_KEY_FLAG_PAIRWISE;

	WARN_ON(key->flags & IEEE80211_KEY_FLAG_PAIRWISE && !sta);
	ieee80211_get_key_rx_seq(key, 0, &seq);
	if (idx < 0)
		return -EINVAL;
	k = &wdev->keys[idx];
	k->IntId = wvif->Id;
	if (key->cipher == WLAN_CIPHER_SUITE_WEP40 || key->cipher ==  WLAN_CIPHER_SUITE_WEP104) {
		if (pairwise)
			k->Type = fill_wep_pair(&k->Key.WepPairwiseKey, key, sta->addr);
		else
			k->Type = fill_wep_group(&k->Key.WepGroupKey, key);
	} else if (key->cipher == WLAN_CIPHER_SUITE_TKIP) {
		if (pairwise)
			k->Type = fill_tkip_pair(&k->Key.TkipPairwiseKey, key, sta->addr);
		else
			k->Type = fill_tkip_group(&k->Key.TkipGroupKey, key, &seq, wvif->mode);
	} else if (key->cipher == WLAN_CIPHER_SUITE_CCMP) {
		if (pairwise)
			k->Type = fill_ccmp_pair(&k->Key.AesPairwiseKey, key, sta->addr);
		else
			k->Type = fill_ccmp_group(&k->Key.AesGroupKey, key, &seq);
	} else if (key->cipher ==  WLAN_CIPHER_SUITE_SMS4) {
		if (pairwise)
			k->Type = fill_sms4_pair(&k->Key.WapiPairwiseKey, key, sta->addr);
		else
			k->Type = fill_sms4_group(&k->Key.WapiGroupKey, key);
	} else if (key->cipher ==  WLAN_CIPHER_SUITE_AES_CMAC) {
		k->Type = fill_aes_cmac_group(&k->Key.IgtkGroupKey, key, &seq);
	} else {
		dev_warn(wdev->dev, "unsupported key type %d\n", key->cipher);
		wfx_free_key(wdev, idx);
		return -EOPNOTSUPP;
	}
	ret = wsm_add_key(wdev, k);
	if (ret) {
#if KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE && \
    KERNEL_VERSION(4, 9, 63) > LINUX_VERSION_CODE && \
    KERNEL_VERSION(4, 4, 99) > LINUX_VERSION_CODE
		if (ret == HI_INVALID_PARAMETER) {
			// Use a patched kernel in order to solve this error
			dev_warn(wdev->dev, "chip prevents re-installation of same key\n");
			dev_warn(wdev->dev, "your kernel is not patched to protect against KRACK attack\n");
		}
#endif
		wfx_free_key(wdev, idx);
		return -EOPNOTSUPP;
	}
#if (KERNEL_VERSION(3, 19, 0) > LINUX_VERSION_CODE)
	key->flags |= IEEE80211_KEY_FLAG_PUT_IV_SPACE;
#else
	key->flags |= IEEE80211_KEY_FLAG_PUT_IV_SPACE |
		      IEEE80211_KEY_FLAG_RESERVE_TAILROOM;
#endif
	key->hw_key_idx = idx;
	return 0;
}

static int wfx_remove_key(struct wfx_vif *wvif, struct ieee80211_key_conf *key)
{
	WARN(key->hw_key_idx > WSM_KEY_MAX_INDEX, "Corrupted hw_key_idx");
	wfx_free_key(wvif->wdev, key->hw_key_idx);
	return wsm_remove_key(wvif->wdev, key->hw_key_idx);
}

int wfx_set_key(struct ieee80211_hw *hw, enum set_key_cmd cmd,
		   struct ieee80211_vif *vif, struct ieee80211_sta *sta,
		   struct ieee80211_key_conf *key)
{
	int ret = -EOPNOTSUPP;
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;

	mutex_lock(&wvif->wdev->conf_mutex);
	if (cmd == SET_KEY)
		ret = wfx_add_key(wvif, sta, key);
	if (cmd == DISABLE_KEY)
		ret = wfx_remove_key(wvif, key);
	mutex_unlock(&wvif->wdev->conf_mutex);
	return ret;
}

int wfx_upload_keys(struct wfx_vif *wvif)
{
	int i;
	WsmHiAddKeyReqBody_t *key;
	struct wfx_dev *wdev = wvif->wdev;

	for (i = 0; i < WSM_KEY_MAX_INDEX; i++) {
		if (wdev->key_map & BIT(i)) {
			key = &wdev->keys[i];
			if (key->IntId == wvif->Id)
				wsm_add_key(wdev, key);
		}
	}
	return 0;
}

void wfx_wep_key_work(struct work_struct *work)
{
	struct wfx_vif *wvif = container_of(work, struct wfx_vif, wep_key_work);
	WsmHiTxReqBody_t *wsm = wfx_skb_txreq(wvif->wep_pending_skb);
	uint32_t packet_id = wsm->PacketId;
	u8 queue_id = wfx_queue_get_queue_id(packet_id);
	struct wfx_queue *queue = &wvif->wdev->tx_queue[queue_id];
	int wep_default_key_id = wvif->wep_default_key_id;

	wsm_tx_flush(wvif->wdev);
	wsm_wep_default_key_id(wvif->wdev, wep_default_key_id, wvif->Id);
	wfx_queue_requeue(queue, packet_id);
	wvif->wep_pending_skb = NULL;
	wsm_tx_unlock(wvif->wdev);
}

