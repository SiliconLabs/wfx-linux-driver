/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
 


/*========================================================================*/
/*                 Standard Linux Headers             					  */
/*========================================================================*/
#include <net/netlink.h>
#include <net/genetlink.h>

/*========================================================================*/
/*                 Local Header files             					      */
/*========================================================================*/
#include "include/wfx_testmode.h"
#include "include/prv_testmode.h"
#include "../wfx.h"
#include "../hwio.h"
#include "../fwio.h"


/**
 * testmode_policy is to be carried through the NL80211_CMD_TESTMODE
 */
static const struct nla_policy wfx_tm_policy[WFX_TM_ATTR_MAX + 1] = {
		[WFX_TM_ATTR_TYPE]			= 	{ .type = NLA_U32 },
		[WFX_TM_ATTR_CMD]			= 	{ .type = NLA_U32 }
};
/**
 * wfx_testmode_cmd -called when testmode command
 * reaches wfx_
 *
 * @hw: the hardware
 * @data: incoming data
 * @len: incoming data length
 *
 * Returns: 0 on success or non zero value on failure
 */
int wfx_testmode_command(struct ieee80211_hw *hw,
		struct ieee80211_vif *vif,
			    void *data, int len)
{
	int ret = 0;
	int err;
	struct nlattr *tb[NLA_MAX_TYPE];

	/*
	 * nla_parse function
	 * Parse a stream of attributes into a tb buffer(see libnl-genl)
	 *
	 * Parses a stream of attributes and stores a pointer to each attribute in
	 * the tb array accessable via the attribute type. Attributes with a type
	 * exceeding maxtype will be silently ignored for backwards compatibility reasons.
	 * policy may be set to NULL if no validation is required.
	 *
	 * @tb			:	destination array with maxtype+1 elements
	 * @maxtype		:	maximum attribute type to be expected
	 * @head		: 	head of attribute stream
	 * @len			: 	length of attribute stream
	 * @policy		: 	validation policy
	 *
	 * Returns: 0 on success or a negative error code.
	 *
	 */
	err = nla_parse(tb,
			NLA_MAX_TYPE,
			data,
			len,
			NULL);

	if(err){
		return err;
	}

	/*
	 * nla_get_u32 function
	 * see libnl-genl
	 *
	 * Parses a stream of attributes and stores a pointer to each attribute in
	 * the tb array accessable via the attribute type. Attributes with a type
	 * exceeding maxtype will be silently ignored for backwards compatibility reasons.
	 * policy may be set to NULL if no validation is required.
	 *
	 * @nla	:	nla u32 netlink attribute
	 *
	 * Returns : payload of u32 attribute.
	 *
	 */
	switch (nla_get_u32(tb[WFX_TM_ATTR_TYPE])) {

	case WFX_TM_ATTR_TYPE_BITSTEAM:
		ret = wfx_testmode_bs(hw,tb);
		break;

	case WFX_TM_ATTR_TYPE_HIF:
		ret = wfx_testmode_hif(hw,tb);
		break;

	default:
		break;
	}
	return ret;
}

