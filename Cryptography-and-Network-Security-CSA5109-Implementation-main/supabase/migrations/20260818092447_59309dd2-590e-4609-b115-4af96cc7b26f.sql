
CREATE POLICY "encrypted_payloads_sender_insert" ON storage.objects FOR INSERT TO authenticated
WITH CHECK (bucket_id = 'encrypted-payloads' AND (storage.foldername(name))[1] = auth.uid()::text);

CREATE POLICY "encrypted_payloads_owner_select" ON storage.objects FOR SELECT TO authenticated
USING (bucket_id = 'encrypted-payloads' AND (storage.foldername(name))[1] = auth.uid()::text);
