package space.pxls.auth;

import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import kong.unirest.json.JSONObject;
import space.pxls.App;

public class LemmyAuthService extends AuthService {
	public LemmyAuthService(String id) {
		super(id, App.getConfig().getBoolean("oauth.lemmy.enabled"),
				App.getConfig().getBoolean("oauth.lemmy.registrationEnabled"));
	}

	private static String getHost() {
		return "https://" + App.getConfig().getString("oauth.lemmy.host");
	}

	@Override
	public String getRedirectUrl(String state) {
		return getHost() + "/auth?client_id=" + App.getConfig().getString("oauth.lemmy.key")
				+ "&response_type=code&state=" + state + "&scope=openid&redirect_uri=" + getCallbackUrl();
	}

	@Override
	public String getToken(String code) throws UnirestException {
		HttpResponse<JsonNode> response = Unirest.post(getHost() + "/token").header("User-Agent", "pxls.space")
				.field("grant_type", "authorization_code").field("code", code).field("redirect_uri", getCallbackUrl())
				.basicAuth(App.getConfig().getString("oauth.lemmy.key"),
						App.getConfig().getString("oauth.lemmy.secret"))
				.asJson();

		JSONObject json = response.getBody().getObject();

		if (json.has("error")) {
			return null;
		} else {
			return json.getString("access_token");
		}
	}

	@Override
	public String getIdentifier(String token) throws UnirestException, InvalidAccountException {
		HttpResponse<JsonNode> me = Unirest.get(getHost() + "/me").header("Authorization", "Bearer " + token)
				.header("User-Agent", "pxls.space").asJson();
		JSONObject json = me.getBody().getObject();
		if (json.has("error")) {
			return null;
		} else {
			return json.getString("sub");
		}
	}

	@Override
	public String getName() {
		return "Lemmy";
	}

	@Override
	public void reloadEnabledState() {
		this.enabled = App.getConfig().getBoolean("oauth.lemmy.enabled");
		this.registrationEnabled = App.getConfig().getBoolean("oauth.lemmy.registrationEnabled");
	}
}
