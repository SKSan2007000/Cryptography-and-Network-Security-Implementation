CREATE POLICY audit_logs_transfer_party_select ON public.audit_logs
FOR SELECT TO authenticated
USING (
  transfer_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM public.transfers t
    WHERE t.id = audit_logs.transfer_id
      AND (t.sender_id = auth.uid() OR t.recipient_id = auth.uid())
  )
);