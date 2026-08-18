import Stripe from "npm:stripe@^22";
import { createClient } from "npm:@supabase/supabase-js@2";

function getSupabaseSecretKey() {
  const modern = Deno.env.get("SUPABASE_SECRET_KEYS");
  if (modern) {
    const parsed = JSON.parse(modern);
    if (parsed.default) return parsed.default as string;
  }
  const legacy = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (legacy) return legacy;
  throw new Error("Clé serveur Supabase introuvable.");
}

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);
const cryptoProvider = Stripe.createSubtleCryptoProvider();

Deno.serve(async (req) => {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });

  const signature = req.headers.get("Stripe-Signature");
  const webhookSecret = Deno.env.get("STRIPE_WEBHOOK_SECRET");
  if (!signature || !webhookSecret) return new Response("Webhook configuration missing", { status: 500 });

  const body = await req.text();
  let event: Stripe.Event;

  try {
    event = await stripe.webhooks.constructEventAsync(
      body,
      signature,
      webhookSecret,
      undefined,
      cryptoProvider,
    );
  } catch (error) {
    console.error("Signature webhook invalide", error);
    return new Response("Invalid signature", { status: 400 });
  }

  try {
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      getSupabaseSecretKey(),
      { auth: { persistSession: false, autoRefreshToken: false } },
    );

    if (
      event.type === "checkout.session.completed" ||
      event.type === "checkout.session.async_payment_succeeded"
    ) {
      const session = event.data.object as Stripe.Checkout.Session;
      const bookingId = session.metadata?.booking_id;

      if (bookingId && session.payment_status !== "unpaid") {
        const { error } = await supabase
          .from("bookings")
          .update({
            status: "paid",
            paid_at: new Date().toISOString(),
            expires_at: null,
            stripe_session_id: session.id,
          })
          .eq("id", bookingId);
        if (error) throw error;
      }
    }

    if (
      event.type === "checkout.session.expired" ||
      event.type === "checkout.session.async_payment_failed"
    ) {
      const session = event.data.object as Stripe.Checkout.Session;
      const bookingId = session.metadata?.booking_id;
      if (bookingId) {
        const { error } = await supabase
          .from("bookings")
          .delete()
          .eq("id", bookingId)
          .eq("status", "pending");
        if (error) throw error;
      }
    }

    return new Response(JSON.stringify({ received: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error(error);
    // Stripe réessaiera automatiquement le webhook si on répond avec une erreur.
    return new Response("Webhook processing error", { status: 500 });
  }
});
